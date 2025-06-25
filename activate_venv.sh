#!/bin/bash
# Virtual Environment Activation Script for Network Mapping Tool

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Network Mapping Tool - Virtual Environment Setup${NC}"
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
    else
        echo -e "${RED}Failed to create virtual environment.${NC}"
        exit 1
    fi
}

# Function to activate virtual environment
activate_venv() {
    if [ -f "$VENV_DIR/bin/activate" ]; then
        echo -e "${YELLOW}Activating virtual environment...${NC}"
        source "$VENV_DIR/bin/activate"
        echo -e "${GREEN}Virtual environment activated.${NC}"
    else
        echo -e "${RED}Virtual environment not found. Creating...${NC}"
        create_venv
        source "$VENV_DIR/bin/activate"
    fi
}

# Function to install requirements
install_requirements() {
    if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
        echo -e "${YELLOW}Installing requirements...${NC}"
        pip install --upgrade pip
        pip install -r "$SCRIPT_DIR/requirements.txt"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Requirements installed successfully.${NC}"
        else
            echo -e "${RED}Failed to install some requirements.${NC}"
        fi
    else
        echo -e "${YELLOW}No requirements.txt found. Skipping...${NC}"
    fi
}

# Main execution
activate_venv
install_requirements

echo -e "${GREEN}Setup complete! You can now run:${NC}"
echo "  - python gui.py         (for GUI version)"
echo "  - python main.py        (for command line version)"
echo "  - python interactive.py (for interactive version)"

# Keep the shell active with the virtual environment
echo -e "${YELLOW}Virtual environment is now active.${NC}"
exec "$SHELL"
