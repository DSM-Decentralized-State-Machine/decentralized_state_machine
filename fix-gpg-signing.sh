#!/bin/bash

# Option 1: Export GPG_TTY environment variable
echo "Configuring GPG_TTY environment variable..."
export GPG_TTY=$(tty)
echo "GPG_TTY set to $GPG_TTY"

# Option 2: Set no-tty option in gpg.conf
echo "Creating/updating gpg.conf with no-tty option..."
mkdir -p ~/.gnupg
echo "no-tty" >> ~/.gnupg/gpg.conf
chmod 700 ~/.gnupg
chmod 600 ~/.gnupg/gpg.conf
echo "gpg.conf updated"

# Option 3: Configure Git to use a different format for commit signing
echo "Configuring Git to handle commit signing better..."
git config --global gpg.program $(which gpg)
git config --global commit.gpgsign true

# Option 4: Configure pinentry program
echo "Configuring pinentry program..."
if [[ "$OSTYPE" == "darwin"* ]]; then
  # macOS specific setup
  echo "Detected macOS system"
  if [ -f "/usr/local/bin/pinentry-mac" ]; then
    echo "pinentry-mac" > ~/.gnupg/gpg-agent.conf
    echo "Updated gpg-agent.conf to use pinentry-mac"
  else
    echo "pinentry-mac not found. If you need a graphical pinentry, install it with: brew install pinentry-mac"
  fi
fi

# Reload the GPG agent
echo "Reloading GPG agent..."
gpgconf --kill gpg-agent
echo "GPG agent reloaded"

echo "Setup complete! Try committing again."
echo "If issues persist, you can temporarily disable signing with: git -c commit.gpgsign=false commit"
