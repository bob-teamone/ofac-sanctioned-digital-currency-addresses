#!/usr/bin/env python3

# SECURITY: Use defusedxml to prevent XXE and Billion Laughs attacks
try:
    import defusedxml.ElementTree as ET
except ImportError:
    raise ImportError("Security critical dependency missing. Please run: pip install defusedxml")

import argparse
import pathlib
import json
import csv
import sys

# ... [CONSTANTS REMAIN THE SAME] ...
FEATURE_TYPE_TEXT = "Digital Currency Address - "
NAMESPACE = {'sdn': 'https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/ADVANCED_XML'}
POSSIBLE_ASSETS = ["XBT", "ETH", "XMR", "LTC", "ZEC", "DASH", "BTG", "ETC",
                   "BSV", "BCH", "XVG", "USDT", "XRP", "ARB", "BSC", "USDC",
                   "TRX"]
OUTPUT_FORMATS = ["TXT", "JSON"]

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Tool to extract sanctioned digital currency addresses from the OFAC XML.')
    
    # Ensure this is always a list for consistency
    parser.add_argument('assets', choices=POSSIBLE_ASSETS, nargs='*',
                        default=[POSSIBLE_ASSETS[0]], 
                        help='Asset to extract (default: XBT)')
    
    parser.add_argument('-sdn', '--special-designated-nationals-list', dest='sdn', 
                        type=pathlib.Path, # Use Path here
                        default=pathlib.Path("./sdn_advanced.xml"),
                        help='Path to sdn_advanced.xml')
                        
    parser.add_argument('-f', '--output-format', dest='format', nargs='+', choices=OUTPUT_FORMATS,
                        default=[OUTPUT_FORMATS[0]], help='Output format')
                        
    parser.add_argument('-path', '--output-path', dest='outpath', type=pathlib.Path, 
                        default=pathlib.Path("./"), help='Output directory')
                        
    return parser.parse_args()

def feature_type_text(asset):
    return f"Digital Currency Address - {asset}"

def get_address_id(root, asset):
    query = f"sdn:ReferenceValueSets/sdn:FeatureTypeValues/*[.='{feature_type_text(asset)}']"
    feature_type = root.find(query, NAMESPACE)
    
    if feature_type is None:
        raise LookupError(f"No FeatureType with the name {feature_type_text(asset)} found")
        
    return feature_type.attrib["ID"]

def get_entity_name(party_element):
    """Extract all aliases of an entity/person from a DistinctParty element, separated by ','."""
    names = []
    
    # Find all aliases in the identity
    for alias in party_element.findall(".//sdn:Profile/sdn:Identity/sdn:Alias", NAMESPACE):
        parts = []
        # Construct the full name from parts (e.g. First Name + Last Name)
        for part in alias.findall(".//sdn:DocumentedName/sdn:DocumentedNamePart/sdn:NamePartValue", NAMESPACE):
            if part.text:
                parts.append(part.text)
        
        if parts:
            names.append(" ".join(parts))
    
    if not names:
        return "Unknown"
    
    # Return unique names separated by semicolon
    return ";".join(dict.fromkeys(names))

def get_sanctioned_addresses(root, address_id):
    """Extract addresses with associated entity/person names.
    
    Returns:
        list of dict: Each dict contains 'address' and 'name' keys
    """
    address_data = []
    
    # Iterate over all DistinctParty elements to maintain context
    for party in root.findall("sdn:DistinctParties/sdn:DistinctParty", NAMESPACE):
        # Search for the specific feature within this party
        query = f".//*[@FeatureTypeID='{address_id}']"
        features = party.findall(query, NAMESPACE)
        
        if features:
            # Get the entity name once for this party
            entity_name = get_entity_name(party)
            
            for feature in features:
                for version_detail in feature.findall(".//sdn:VersionDetail", NAMESPACE):
                    if version_detail.text:
                        address_data.append({
                            'address': version_detail.text,
                            'name': entity_name
                        })
    
    return address_data

def write_addresses(address_data, asset, output_formats, outpath):
    """Write addresses with entity names to output files.
    
    Args:
        address_data: list of dict with 'address' and 'name' keys
        asset: asset type string
        output_formats: list of output format strings
        outpath: Path object for output directory
    """
    # Ensure directory exists
    if not outpath.exists():
        try:
            outpath.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            print(f"Error creating directory {outpath}: {e}", file=sys.stderr)
            return

    base_filename = f"sanctioned_addresses_{asset}"

    if "TXT" in output_formats:
        file_path = outpath / f"{base_filename}.txt"
        with open(file_path, 'w', encoding='utf-8', newline='') as out:
            writer = csv.writer(out, delimiter=';')
            for item in address_data:
                writer.writerow([item['address'], item['name']])

    if "JSON" in output_formats:
        file_path = outpath / f"{base_filename}.json"
        with open(file_path, 'w', encoding='utf-8') as out:
            json.dump(address_data, out, indent=2, ensure_ascii=False)

def main():
    args = parse_arguments()

    if not args.sdn.exists():
        print(f"Error: Input file {args.sdn} not found.", file=sys.stderr)
        sys.exit(1)

    try:
        # Secure parsing
        tree = ET.parse(args.sdn)
    except Exception as e:
        print(f"Failed to parse XML: {e}", file=sys.stderr)
        sys.exit(1)
        
    root = tree.getroot()

    # Normalization of args is handled by argparse configuration now
    assets = args.assets if isinstance(args.assets, list) else [args.assets]
    output_formats = args.format if isinstance(args.format, list) else [args.format]

    for asset in assets:
        try:
            address_id = get_address_id(root, asset)
            address_data = get_sanctioned_addresses(root, address_id)
            
            # Efficient deduplication by address while preserving names
            seen_addresses = {}
            for item in address_data:
                addr = item['address']
                if addr not in seen_addresses:
                    seen_addresses[addr] = item['name']
            
            # Sort and reconstruct
            address_data = [{'address': addr, 'name': name} 
                          for addr, name in sorted(seen_addresses.items())]
            
            write_addresses(address_data, asset, output_formats, args.outpath)
            print(f"Successfully processed {len(address_data)} addresses for {asset}")
            
        except LookupError as e:
            print(f"Warning: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
