#!/usr/bin/env python3
import sys
import copy
import os.path
import lxml.etree

def read_base_xml(filename):
    with open(filename, "rb") as cobertura_file:
        return lxml.etree.fromstring(cobertura_file.read())

def create_header_node(cobertura):
    header_node = copy.deepcopy(cobertura)
    packages_node = header_node.find('packages')

    if packages_node is not None:
        # Delete all the package nodes from the copied XML
        for package_to_remove in packages_node:
            packages_node.remove(package_to_remove)

    return header_node

def create_package_file(cobertura_header, package, destination_path, package_number):
    filename = f"cobertura-{package_number}.xml"
    full_path = os.path.join(destination_path, filename)
    print(f"Creating package file {full_path}")

    xml_to_write = copy.deepcopy(cobertura_header)
    packages_node = xml_to_write.find('packages')

    # Add back the one package we want
    packages_node.append(package)

    # Write the new XML tree safely
    with open(full_path, 'wb') as package_file:
        package_file.write(lxml.etree.tostring(
            xml_to_write,
            encoding='UTF-8',
            xml_declaration=True,
            pretty_print=True
        ))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: split-coverage.py FILENAME [DESTINATION_PATH]")
        sys.exit(1)

    filename = sys.argv[1]
    destination_path = sys.argv[2] if len(sys.argv) > 2 else "."

    print(f"Reading in Cobertura XML from {filename}")
    cobertura_xml = read_base_xml(filename)
    cobertura_header = create_header_node(cobertura_xml)

    packages_node = cobertura_xml.find('packages')
    if packages_node is not None:
        packages = list(packages_node)

        for package_number, package in enumerate(packages, start=1):
            create_package_file(cobertura_header, package, destination_path, package_number)
            package_number += 1
    else:
        print("No <packages> node found in the source XML.")
