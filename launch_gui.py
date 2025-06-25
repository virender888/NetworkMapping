#!/usr/bin/env python3
"""
GUI Launcher with Virtual Environment Support
This script sets up the virtual environment and launches the GUI
"""

import os
import sys
import subprocess
import venv
from pathlib import Path

def print_colored(text, color=""):
    """Print colored text to console"""
    colors = {
        'red': '\033[0;31m',
        'green': '\033[0;32m',
        'yellow': '\033[1;33m',
        'blue': '\033[0;34m',
        'reset': '\033[0m'
    }
    
    if color in colors:
        print(f"{colors[color]}{text}{colors['reset']}")
    else:
        print(text)

def setup_venv():
    """Setup virtual environment"""
    script_dir = Path(__file__).parent
    venv_dir = script_dir / "venv"
    
    if not venv_dir.exists():
        print_colored("Creating virtual environment...", "yellow")
        try:
            venv.create(venv_dir, with_pip=True)
            print_colored("Virtual environment created successfully.", "green")
        except Exception as e:
            print_colored(f"Failed to create virtual environment: {e}", "red")
            return False
    
    return True

def install_requirements():
    """Install requirements in virtual environment"""
    script_dir = Path(__file__).parent
    venv_dir = script_dir / "venv"
    requirements_file = script_dir / "requirements.txt"
    
    if not requirements_file.exists():
        print_colored("No requirements.txt found. Continuing...", "yellow")
        return True
    
    # Determine pip executable path
    if sys.platform == "win32":
        pip_exe = venv_dir / "Scripts" / "pip.exe"
        python_exe = venv_dir / "Scripts" / "python.exe"
    else:
        pip_exe = venv_dir / "bin" / "pip"
        python_exe = venv_dir / "bin" / "python"
    
    if not pip_exe.exists():
        print_colored("pip not found in virtual environment", "red")
        return False
    
    print_colored("Installing requirements...", "yellow")
    try:
        # Upgrade pip first
        subprocess.run([str(python_exe), "-m", "pip", "install", "--upgrade", "pip"], 
                      check=True, capture_output=True)
        
        # Install requirements
        subprocess.run([str(pip_exe), "install", "-r", str(requirements_file)], 
                      check=True, capture_output=True)
        
        print_colored("Requirements installed successfully.", "green")
        return True
    except subprocess.CalledProcessError as e:
        print_colored(f"Failed to install requirements: {e}", "red")
        return False

def check_gui_support():
    """Check if GUI (tkinter) is available"""
    try:
        import tkinter
        return True
    except ImportError:
        print_colored("Error: tkinter is not available in your Python installation.", "red")
        print_colored("Please install tkinter or use the command-line version:", "yellow")
        print("  python3 main.py")
        return False

def run_gui():
    """Run the GUI application"""
    script_dir = Path(__file__).parent
    venv_dir = script_dir / "venv"
    gui_script = script_dir / "gui.py"
    
    # Determine python executable path
    if sys.platform == "win32":
        python_exe = venv_dir / "Scripts" / "python.exe"
    else:
        python_exe = venv_dir / "bin" / "python"
    
    if not python_exe.exists():
        print_colored("Python executable not found in virtual environment", "red")
        return False
    
    if not gui_script.exists():
        print_colored("GUI script not found", "red")
        return False
    
    print_colored("Starting GUI...", "green")
    try:
        # Change to script directory and run GUI
        os.chdir(script_dir)
        subprocess.run([str(python_exe), str(gui_script)], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print_colored(f"GUI failed to start: {e}", "red")
        return False
    except KeyboardInterrupt:
        print_colored("\nGUI closed by user.", "yellow")
        return True

def main():
    """Main function"""
    print_colored("Enhanced Network Mapping Tool - GUI Launcher", "blue")
    print("=" * 50)
    
    # Check GUI support first
    if not check_gui_support():
        sys.exit(1)
    
    # Setup virtual environment
    print_colored("Setting up environment...", "yellow")
    if not setup_venv():
        sys.exit(1)
    
    # Install requirements
    if not install_requirements():
        print_colored("Failed to install requirements. Exiting.", "red")
        sys.exit(1)
    
    # Run GUI
    print_colored("Environment ready!", "green")
    if not run_gui():
        print_colored("GUI failed to start. You can try the command-line version:", "red")
        print("  python3 main.py")
        sys.exit(1)

if __name__ == "__main__":
    main()
