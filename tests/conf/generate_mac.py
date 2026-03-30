import random
import sys

def generate_random_mac():
    """Generates a single random MAC address with mixed casing."""
    mac_parts = []
    for _ in range(6):  # 6 octets in a MAC address
        octet = ""
        for _ in range(2):  # 2 hex digits per octet
            val = random.randint(0, 15)
            char = hex(val)[2:]  # Convert to hex (stripping the '0x')

            # If the character is a letter (a-f), randomize its case
            if char.isalpha():
                char = random.choice([char.lower(), char.upper()])

            octet += char
        mac_parts.append(octet)

    return ":".join(mac_parts)

def get_test_macs(total_count, special_macs=None):
    """Generates unique MAC addresses, always including the special ones."""
    if special_macs is None:
        special_macs = []

    # Initialize the set with your special MACs to guarantee they are included
    unique_macs = set(special_macs)

    # Ensure our target count doesn't cut off any of the special MACs
    target_count = max(total_count, len(unique_macs))

    # Fill the remainder of the target count with random unique MACs
    while len(unique_macs) < target_count:
        unique_macs.add(generate_random_mac())

    # Convert back to a list to shuffle them so the special MACs
    # aren't always clustered together or at the front of the string
    mac_list = list(unique_macs)
    random.shuffle(mac_list)

    return mac_list

# --- Configuration ---

# Add your mandatory MAC addresses here. They will always be included.
SPECIAL_MACS = [
    "00:00:00:00:00:00",
    "FF:FF:FF:FF:FF:FF"
]

# The default total number of MACs if no argument is provided
DEFAULT_TOTAL_MACS = 10

if __name__ == "__main__":
    total_macs = DEFAULT_TOTAL_MACS

    # Check if a command line argument was provided
    if len(sys.argv) > 1:
        try:
            total_macs = int(sys.argv[1])
        except ValueError:
            # If the argument isn't a valid integer, print an error to standard error
            # and continue with the default value.
            print(f"Warning: '{sys.argv[1]}' is not a valid number. Using default: {DEFAULT_TOTAL_MACS}", file=sys.stderr)
            total_macs = DEFAULT_TOTAL_MACS

    # Generate the combined list
    mac_addresses = get_test_macs(total_macs, SPECIAL_MACS)

    # Join the set into a single string separated by a single comma
    output = ",".join(mac_addresses)

    print(output)

