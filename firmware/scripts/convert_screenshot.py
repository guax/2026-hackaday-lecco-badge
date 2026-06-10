#!/usr/bin/env python3
import sys
import struct
import argparse
from PIL import Image

"""
Screenshots can be taken on device using the jolly rancher + p key combination.
Its a bit finicky but it does work. You then copy the raw file out of the device with mpremote and convert it.
Example:
    mpremote cp :/screenshot_11658.raw .
    ./convert_screenshot.py screenshot_11658.raw screenshot_11658.png
"""
def convert_rgb565_to_png(input_path, output_path, width=428, height=142, swap=False):
    with open(input_path, "rb") as f:
        data = f.read()

    expected_size = width * height * 2
    if len(data) != expected_size:
        print(f"Warning: Expected {expected_size} bytes for a {width}x{height} image, but got {len(data)} bytes.")

    img = Image.new("RGB", (width, height))
    pixels = img.load()
    
    idx = 0
    for y in range(height):
        for x in range(width):
            if idx + 2 > len(data):
                break
            
            fmt = ">H" if swap else "<H"
            pixel = struct.unpack(fmt, data[idx:idx+2])[0]
            
            # Extract RGB components from RGB565
            r = (pixel >> 11) & 0x1F
            g = (pixel >> 5) & 0x3F
            b = pixel & 0x1F
            
            # Scale up to 0-255
            r = (r * 255) // 31
            g = (g * 255) // 63
            b = (b * 255) // 31
            
            pixels[x, y] = (r, g, b)
            idx += 2

    img.save(output_path)
    print(f"Successfully converted {input_path} to {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert an LVGL RGB565 .raw screenshot to .png")
    parser.add_argument("input", help="Input .raw file from the badge")
    parser.add_argument("output", help="Output .png file")
    parser.add_argument("--width", type=int, default=428, help="Width of the screenshot (default: 428)")
    parser.add_argument("--height", type=int, default=142, help="Height of the screenshot (default: 142)")
    parser.add_argument("--swap", action="store_true", help="Swap byte order (try this if the colors look mangled)")
    
    args = parser.parse_args()
    
    try:
        convert_rgb565_to_png(args.input, args.output, args.width, args.height, args.swap)
    except Exception as e:
        print(f"Error converting file: {e}")
        sys.exit(1)
