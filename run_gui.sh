#!/bin/bash
# GUI Launcher Script with Virtual Environment Support

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Enhanced Network Mapping Tool - GUI Launcher${NC}"
echo "================================================"

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
VENV_DIR="$SCRIPT_DIR/venv"

# Function to create virtual environment
create_venv() {
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv "$VENV_DIR"
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Virtual environment created successfully.${NC}"
        return 0
    else
        echo -e "${RED}Failed to create virtual environment.${NC}"
        return 1
    fi
}

# Function to activate virtual environment
activate_venv() {
    if [ -f "$VENV_DIR/bin/activate" ]; then
        echo -e "${GREEN}Activating virtual environment...${NC}"
        source "$VENV_DIR/bin/activate"
        return 0
    else
        echo -e "${YELLOW}Virtual environment not found. Creating...${NC}"
        if create_venv; then
            source "$VENV_DIR/bin/activate"
            return 0
        else
            return 1
        fi
    fi
}

# Function to install requirements
install_requirements() {
    if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
        echo -e "${YELLOW}Checking and installing requirements...${NC}"
        pip install --upgrade pip > /dev/null 2>&1
        pip install -r "$SCRIPT_DIR/requirements.txt" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Requirements satisfied.${NC}"
            return 0
        else
            echo -e "${RED}Failed to install some requirements.${NC}"
            return 1
        fi
    else
        echo -e "${YELLOW}No requirements.txt found. Continuing...${NC}"
        return 0
    fi
}

# Function to check if GUI can run
check_gui_support() {
    python3 -c "import tkinter" 2>/dev/null
    if [ $? -eq 0 ]; then
        return 0
    else
        echo -e "${RED}Error: tkinter is not available in your Python installation.${NC}"
        echo -e "${YELLOW}Please install tkinter or use the command-line version:${NC}"
        echo "  python3 main.py"
        return 1
    fi
}

# Main execution
echo -e "${YELLOW}Setting up environment...${NC}"

# Check GUI support first
if ! check_gui_support; then
    exit 1
fi

# Setup virtual environment
if activate_venv; then
    if install_requirements; then
        echo -e "${GREEN}Environment ready! Starting GUI...${NC}"
        echo ""
        
        # Change to script directory and run GUI
        cd "$SCRIPT_DIR"
        python3 gui.py
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}GUI failed to start. You can try the command-line version:${NC}"
            echo "  python3 main.py"
        fi
    else
        echo -e "${RED}Failed to install requirements. Exiting.${NC}"
        exit 1
    fi
else
    echo -e "${RED}Failed to setup virtual environment. Exiting.${NC}"
    exit 1
fi
