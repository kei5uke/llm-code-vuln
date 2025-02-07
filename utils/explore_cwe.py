import xml.etree.ElementTree as ET

# Parse the XML file
tree = ET.parse("./dataset/cwe.xml")
root = tree.getroot()
ns = {"cwe": "http://cwe.mitre.org/cwe-7"} # Define namespace
cwe_dict = {weakness.get("ID"): weakness for weakness in root.findall(".//cwe:Weakness", ns)}

# Function that tells type
def get_type(cwe_id:str):
    weakness = cwe_dict.get(cwe_id)
    abstraction = weakness.get("Abstraction")
    return abstraction

def find_parents_dict(cwe_id:str):    
    result = {"Pillar": [], "Class": [], "Base": [], "Variant": []}
    
    current_cwe_id = cwe_id
    while current_cwe_id:    
        # Find the Weakness element
        weakness = cwe_dict.get(current_cwe_id)
        if not weakness:
            return None  # If CWE is not found, stop the search

        abstraction = weakness.get("Abstraction")
        if (result.get(abstraction, None)) is not None:
            result[abstraction].append('CWE-'+current_cwe_id)
        
        # Check if the weakness abstraction is "Pillar"
        if abstraction == "Pillar": break

        # Find the Parent CWE (ChildOf relation)
        related_weaknesses = weakness.find("cwe:Related_Weaknesses", ns)
        if related_weaknesses is not None:
            for related in related_weaknesses.findall("cwe:Related_Weakness", ns):
                if related.get("Nature") == "ChildOf":
                    current_cwe_id = related.get("CWE_ID")
        else: break
    
    return result