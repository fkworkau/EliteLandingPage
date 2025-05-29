
#!/usr/bin/env python3
"""
Elite Toolkit Builder Script
Easy-to-use builder for the educational cybersecurity toolkit
"""

import os
import sys
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(
        description="Build Elite Cybersecurity Education Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 build_toolkit.py                    # Build in default directory
  python3 build_toolkit.py -o my_toolkit     # Build in custom directory
  python3 build_toolkit.py --demo            # Run quick demonstration
        """
    )
    
    parser.add_argument(
        '-o', '--output',
        default='educational_toolkit',
        help='Output directory for toolkit (default: educational_toolkit)'
    )
    
    parser.add_argument(
        '--demo',
        action='store_true',
        help='Run quick demonstration of toolkit features'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Elite Toolkit Builder 2.0.0'
    )
    
    args = parser.parse_args()
    
    # Import the toolkit (assuming it's in the same directory)
    try:
        from elite_toolkit import EliteToolkitBuilder
    except ImportError:
        print("Error: Cannot import elite_toolkit.py")
        print("Make sure elite_toolkit.py is in the same directory")
        return 1
    
    if args.demo:
        print("=== QUICK DEMONSTRATION ===")
        print("This would show toolkit capabilities...")
        print("For full demonstration, build the toolkit first.")
        return 0
    
    # Build the toolkit
    print(f"Building educational toolkit in: {args.output}")
    
    builder = EliteToolkitBuilder()
    success = builder.create_toolkit_bundle(args.output)
    
    if success:
        print(f"\n✅ Toolkit built successfully in: {args.output}")
        print(f"📁 Check the {args.output} directory for all files")
        print(f"📖 Read {args.output}/README.md for usage instructions")
    else:
        print("\n❌ Failed to build toolkit")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
