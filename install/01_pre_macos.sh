if [ -d "/Applications/Xcode.app" ]; then
  msg_error "Not Found" "You must have Xcode installed to continue."
  exit 1
fi

if xcode-select --install 2>&1 | grep installed; then
  msg_ok "Xcode CLI tools installed";
else
  msg_error "Xcode CLI tools not installed" "Installing..."
fi
