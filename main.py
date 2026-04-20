# Через CPE (рекомендуется для C/C++)
set -a && source .env && set +a

python3 scanner.py \
    --cpe "cpe:2.3:a:wireshark:wireshark:4.4.0:*:*:*:*:*:*:*" \
    --vcs-url "https://github.com/wireshark/wireshark" \
    --version "4.4.0"
