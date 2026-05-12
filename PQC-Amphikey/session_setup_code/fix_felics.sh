#!/bin/bash
# fix_felics.sh — Patch FELICS tag_verification.c to compile on PC/Linux
#
# Problem:  cipher.h defines RAM_DATA_BYTE as "uint8_t ALIGNED" where ALIGNED
#           is a platform macro. On PC/Linux without -DPC, ALIGNED expands to
#           nothing OR something invalid, causing:
#             tag_verification.c:55: error: expected initializer before 'generated_tag'
#
# Fix:      Replace the RAM_DATA_BYTE variable declaration directly with
#           plain uint8_t — no macros, no platform flags needed.

TAG_VER="$HOME/raccoon/ref-c/FELICS-master/authenticated_ciphers/source/common/tag_verification.c"

if [ ! -f "$TAG_VER" ]; then
    echo "ERROR: Cannot find tag_verification.c at:"
    echo "  $TAG_VER"
    exit 1
fi

# Restore original backup first (clean slate in case previous patch was applied)
if [ -f "${TAG_VER}.orig" ]; then
    cp "${TAG_VER}.orig" "$TAG_VER"
    echo "Restored original from backup."
else
    cp "$TAG_VER" "${TAG_VER}.orig"
    echo "Backed up original to: ${TAG_VER}.orig"
fi

# Replace "RAM_DATA_BYTE generated_tag" with "uint8_t generated_tag"
# This sidesteps both RAM_DATA_BYTE and ALIGNED entirely.
sed -i 's/RAM_DATA_BYTE[[:space:]]\+generated_tag/uint8_t generated_tag/g' "$TAG_VER"

# Verify the patch took effect
if grep -q "uint8_t generated_tag" "$TAG_VER"; then
    echo "Patched:  $TAG_VER"
    echo "Done. Now run: make"
else
    echo "ERROR: sed replacement did not apply. Check the file manually:"
    echo "  $TAG_VER"
    grep -n "generated_tag\|RAM_DATA_BYTE" "$TAG_VER"
    exit 1
fi
