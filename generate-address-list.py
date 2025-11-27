#!/usr/bin/env python3

# SECURITY: Use defusedxml to prevent XXE and Billion Laughs attacks
try:
    import defusedxml.ElementTree as ET
except ImportError:
    raise ImportError("Security critical dependency missing. Please run: pip install defusedxml")

import argparse
import pathlib
import json
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

def get_sanctioned_addresses(root, address_id):
    addresses = []
    # Use f-string for cleaner syntax
    query = f"sdn:DistinctParties//*[@FeatureTypeID='{address_id}']"
    
    for feature in root.findall(query, NAMESPACE):
        for version_detail in feature.findall(".//sdn:VersionDetail", NAMESPACE):
            if version_detail.text:
                addresses.append(version_detail.text)
    return addresses

def write_addresses(addresses, asset, output_formats, outpath):
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
        with open(file_path, 'w', encoding='utf-8') as out:
            for address in addresses:
                out.write(f"{address}\n")

    if "JSON" in output_formats:
        file_path = outpath / f"{base_filename}.json"
        with open(file_path, 'w', encoding='utf-8') as out:
            json.dump(addresses, out, indent=2)

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
            addresses = get_sanctioned_addresses(root, address_id)
            
            # Efficient deduplication and sorting
            addresses = sorted(set(addresses))
            
            write_addresses(addresses, asset, output_formats, args.outpath)
            print(f"Successfully processed {len(addresses)} addresses for {asset}")
            
        except LookupError as e:
            print(f"Warning: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
