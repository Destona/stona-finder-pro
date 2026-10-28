#!/data/data/com.termux/files/usr/bin/bash
# STONA FINDER PRO — Termux
# Reconhecimento passivo e testes HTTP/TLS limitados em domínios autorizados.
set -u
APP="$HOME/.stona-finder"
OUT="$APP/results"
mkdir -p "$OUT"
RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BLUE=$'\033[34m'
CYAN=$'\033[36m'; MAGENTA=$'\033[35m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
pause(){ printf '\n%sPrima Enter para voltar ao menu...%s' "$CYAN" "$RESET"; read -r _; }
valid_domain(){ [[ "$1" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]; }
ask_domain(){
  printf '%sDomínio (ex.: unitel.ao): %s' "$CYAN" "$RESET"; read -r DOMAIN
  DOMAIN="${DOMAIN#https://}"; DOMAIN="${DOMAIN#http://}"; DOMAIN="${DOMAIN%%/*}"; DOMAIN="${DOMAIN%%:*}"; DOMAIN="${DOMAIN,,}"
  if ! valid_domain "$DOMAIN"; then printf '%sDomínio inválido.%s\n' "$RED" "$RESET"; return 1; fi
}
stamp(){ date '+%Y%m%d_%H%M%S'; }
banner(){
 clear 2>/dev/null || true
 printf '%s' "$CYAN"
 echo '  ____ _____ ___  _   _    _    '
 echo ' / ___|_   _/ _ \| \ | |  / \   '
 echo ' \___ \ | || | | |  \| | / _ \  '
 echo '  ___) || || |_| | |\  |/ ___ \ '
 echo ' |____/ |_| \___/|_| \_/_/   \_\'
 printf '%s' "$MAGENTA"
 echo '          STONA FINDER PRO'
 printf '%s%s' "$RESET" "$RESET"
 echo '       Domain • Subdomain • SNI/TLS'
 echo
}
dns_check(){
 ask_domain || return
 local file="$OUT/dns_${DOMAIN}_$(stamp).txt"
 { echo "STONA FINDER — DNS $DOMAIN"; echo "Data: $(date)"
   for typ in A AAAA CNAME NS MX TXT; do
     echo; echo "=== $typ ==="; dig +time=3 +tries=1 +noall +answer "$DOMAIN" "$typ" 2>&1
   done
 } | tee "$file"
 printf '%sGuardado: %s%s\n' "$GREEN" "$file" "$RESET"
}
find_subdomains(){
 ask_domain || return
 local file="$OUT/subdomains_${DOMAIN}_$(stamp).txt" raw="$OUT/.crt_$$.json"
 printf '%s[+] A consultar Certificate Transparency...%s\n' "$YELLOW" "$RESET"
 if ! curl -fsSL --max-time 35 "https://crt.sh/?q=%25.${DOMAIN}&output=json" -o "$raw"; then
   printf '%sFalha na consulta; verifica a Internet ou tenta mais tarde.%s\n' "$RED" "$RESET"; rm -f "$raw"; return
 fi
 python - "$DOMAIN" "$raw" "$file" <<'PY'
import json,sys
from pathlib import Path
d,src,out=sys.argv[1:]
try: data=json.loads(Path(src).read_text(errors="replace"))
except Exception as e: print("Erro ao ler a resposta:",e); raise SystemExit(1)
names=set()
for row in data if isinstance(data,list) else []:
 for raw in str(row.get("name_value","")).splitlines():
  n=raw.strip().lower().rstrip(".").lstrip("*.")
  if (n==d or n.endswith("."+d)) and len(n)<=253 and all(p and len(p)<=63 for p in n.split(".")): names.add(n)
items=sorted(names)
Path(out).write_text(f"STONA FINDER PRO\nBase: {d}\nTotal: {len(items)}\n\n"+("\n".join(items)+"\n" if items else "Nenhum nome encontrado.\n"))
print(f"\nTotal encontrado: {len(items)}")
for n in items[:100]: print("  "+n)
if len(items)>100: print(f"... {len(items)-100} nomes adicionais no relatório.")
print("Relatório:",out)
PY
 rm -f "$raw"
 printf '%sNota: os nomes públicos podem estar antigos ou inativos.%s\n' "$YELLOW" "$RESET"
}
tls_check(){
 ask_domain || return
 local port file ca="$PREFIX/etc/tls/cert.pem"
 printf 'Porta TLS [443]: '; read -r port; port="${port:-443}"
 [[ "$port" =~ ^[0-9]{1,5}$ ]] && ((port>=1 && port<=65535)) || { echo "Porta inválida"; return; }
 file="$OUT/tls_${DOMAIN}_${port}_$(stamp).txt"
 printf '%s[+] A testar TLS com SNI %s...%s\n' "$YELLOW" "$DOMAIN" "$RESET"
 {
 echo "STONA FINDER PRO — TLS/SNI $DOMAIN:$port"; echo "Data: $(date)"; echo
 if [[ -r "$ca" ]]; then
  timeout 15 openssl s_client -connect "${DOMAIN}:${port}" -servername "$DOMAIN" -verify_hostname "$DOMAIN" -CAfile "$ca" </dev/null 2>&1
 else
  timeout 15 openssl s_client -connect "${DOMAIN}:${port}" -servername "$DOMAIN" -verify_hostname "$DOMAIN" </dev/null 2>&1
 fi
 echo; echo "=== Certificado ==="
 timeout 15 openssl s_client -connect "${DOMAIN}:${port}" -servername "$DOMAIN" -showcerts </dev/null 2>/dev/null |
  openssl x509 -noout -subject -issuer -dates -fingerprint -sha256 2>&1
 } | tee "$file"
 printf '%sGuardado: %s%s\n' "$GREEN" "$file" "$RESET"
}
http_probe(){
 local host="$1" url code label color
 for url in "https://${host}/" "http://${host}/"; do
  code="$(curl -k -L -sS -o /dev/null -w '%{http_code}' --connect-timeout 4 --max-time 8 "$url" 2>/dev/null || true)"
  [[ -n "$code" ]] || code=000
  case "$code" in
   200) label="HTTP 200 OK"; color="$GREEN";;
   201|202|204) label="HTTP $code OK"; color="$GREEN";;
   301|302|303|307|308) label="HTTP $code REDIRECT"; color="$YELLOW";;
   401|403) label="HTTP $code RESTRITO"; color="$YELLOW";;
   404) label="HTTP 404 NÃO ENCONTRADO"; color="$YELLOW";;
   500|502|503|504) label="HTTP $code ERRO SERVIDOR"; color="$RED";;
   000) continue;;
   *) label="HTTP $code"; color="$BLUE";;
  esac
  printf '%s%-38s %-30s%s\n' "$color" "$host" "$label" "$RESET"; return 0
 done
 printf '%s%-38s SEM RESPOSTA HTTP (DNS/rede/timeout/TLS)%s\n' "$RED" "$host" "$RESET"
}
status_check(){
 ask_domain || return
 local file="$OUT/status_${DOMAIN}_$(stamp).txt"
 { echo "STONA FINDER PRO — HTTP status"; echo "$DOMAIN"; http_probe "$DOMAIN"; } | tee "$file"
 printf '%sGuardado: %s%s\n' "$GREEN" "$file" "$RESET"
 printf '%sNota: HTTP 404 prova que o servidor respondeu; só a página pedida não foi encontrada.%s\n' "$YELLOW" "$RESET"
}
status_list(){
 local list file host count=0
 printf 'Caminho do relatório de subdomínios (ex.: %s/subdomains_example.com_DATA.txt): ' "$OUT"; read -r list
 list="${list/#\~/$HOME}"
 [[ -f "$list" ]] || { printf '%sFicheiro não encontrado.%s\n' "$RED" "$RESET"; return; }
 file="$OUT/status_list_$(stamp).txt"
 echo "Verificação limitada a 100 hosts do ficheiro indicado."
 while IFS= read -r host; do
  host="${host//$'\r'/}"
  [[ -z "$host" || "$host" == \#* ]] && continue
  [[ "$host" =~ ^([A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$ ]] || continue
  http_probe "$host" | tee -a "$file"
  count=$((count+1)); ((count>=100)) && { echo "Limite de 100 hosts atingido."; break; }
  sleep 0.3
 done < "$list"
 printf '%sRelatório: %s%s\n' "$GREEN" "$file" "$RESET"
}

# Pesquisa complementar de nomes comuns: usar apenas em domínios autorizados.
wordlist_scan(){
 ask_domain || return
 local base="$DOMAIN" file="$OUT/wordlist_${DOMAIN}_$(stamp).txt" sub host ip found=0 checked=0
 local -a words=(www api app m mail web portal login cdn static media img images assets ns1 ns2 dns vpn status help support account selfcare recargas tv streaming video wap mms billing payment auth gateway edge cache)
 printf '%sPesquisa DNS limitada para %s (%d nomes)...%s\n' "$YELLOW" "$base" "${#words[@]}" "$RESET"
 echo "STONA FINDER PRO — pesquisa complementar de subdomínios: $base" > "$file"
 for sub in "${words[@]}"; do
  host="$sub.$base"
  ip="$(dig +time=2 +tries=1 +short A "$host" | head -n 1)"
  checked=$((checked+1))
  if [[ -n "$ip" ]]; then
   printf '%s[ENCONTRADO]%s %-38s A %s\n' "$GREEN" "$RESET" "$host" "$ip" | tee -a "$file"
   found=$((found+1))
  fi
  sleep 0.2
 done
 printf '\nVerificados: %d | nomes com registo A: %d\nRelatório: %s\n' "$checked" "$found" "$file"
 printf '%sNota: DNS wildcard pode produzir falsos positivos; confirme os resultados manualmente.%s\n' "$YELLOW" "$RESET"
}

# Diagnóstico de um único host: IP, tempo de ligação TCP, cabeçalhos e indícios de CDN.
network_diagnostics(){
 ask_domain || return
 local host="$DOMAIN" ip start end ms headers server via cf file="$OUT/diagnostico_${DOMAIN}_$(stamp).txt"
 ip="$(dig +time=3 +tries=1 +short A "$host" | head -n 1)"
 [[ -n "$ip" ]] || ip="Sem registo A"
 printf '%s=== Diagnóstico: %s ===%s\nIP IPv4: %s\n' "$CYAN" "$host" "$RESET" "$ip" | tee "$file"
 start="$(date +%s%3N 2>/dev/null || date +%s)"
 if timeout 4 bash -c 'exec 3<>/dev/tcp/"$1"/443' _ "$host" 2>/dev/null; then
  end="$(date +%s%3N 2>/dev/null || date +%s)"
  if [[ "$start" =~ ^[0-9]+$ && "$end" =~ ^[0-9]+$ ]]; then ms=$((end-start)); else ms="indisponível"; fi
  printf 'Ligação TCP/443: %sOK%s | tempo aproximado: %sms\n' "$GREEN" "$RESET" "$ms" | tee -a "$file"
 else
  printf 'Ligação TCP/443: %ssem ligação/timeout%s\n' "$RED" "$RESET" | tee -a "$file"
 fi
 headers="$(curl -k -sS -I -L --max-redirs 3 --connect-timeout 4 --max-time 8 "https://$host/" 2>/dev/null || true)"
 server="$(printf '%s\n' "$headers" | awk 'BEGIN{IGNORECASE=1} /^server:/{sub(/^[^:]*:[[:space:]]*/,""); print; exit}')"
 via="$(printf '%s\n' "$headers" | awk 'BEGIN{IGNORECASE=1} /^via:/{sub(/^[^:]*:[[:space:]]*/,""); print; exit}')"
 cf="$(printf '%s\n' "$headers" | awk 'BEGIN{IGNORECASE=1} /^cf-ray:/{print; exit}')"
 printf 'Cabeçalho Server: %s\nVia: %s\n' "${server:-não divulgado}" "${via:-não divulgado}" | tee -a "$file"
 if [[ -n "$cf" || "${server,,}" == *cloudflare* ]]; then
  printf '%sIndício de CDN: Cloudflare%s\n' "$MAGENTA" "$RESET" | tee -a "$file"
 elif [[ "${server,,}" == *cloudfront* || "${via,,}" == *cloudfront* ]]; then
  printf '%sIndício de CDN: CloudFront%s\n' "$MAGENTA" "$RESET" | tee -a "$file"
 elif [[ "${server,,}" == *akamai* || "${via,,}" == *akamai* ]]; then
  printf '%sIndício de CDN: Akamai%s\n' "$MAGENTA" "$RESET" | tee -a "$file"
 else
  printf 'CDN: não identificada (não significa ligação direta)\n' | tee -a "$file"
 fi
 printf '\n' | tee -a "$file"
 http_probe "$host" | tee -a "$file"
 printf '%sRelatório: %s%s\n' "$GREEN" "$file" "$RESET"
}

operator_catalog(){
 local choice
 printf '%sCatálogo de domínios públicos (confirma a grafia oficial antes de testar):%s\n' "$CYAN" "$RESET"
 printf ' 1) Unitel Angola       unitel.ao\n 2) Africell Angola     africell.ao\n 3) Movicel Angola      movicel.co.ao\n 4) ZAP Angola          zap.co.ao\n 5) Vodacom Moçambique  vodacom.co.mz\n 6) Movitel Moçambique  movitel.co.mz\n 7) Tmcel Moçambique    tmcel.mz\n 0) Voltar\n'
 printf 'Escolha: '; read -r choice
 case "$choice" in
  1) DOMAIN=unitel.ao;; 2) DOMAIN=africell.ao;; 3) DOMAIN=movicel.co.ao;; 4) DOMAIN=zap.co.ao;;
  5) DOMAIN=vodacom.co.mz;; 6) DOMAIN=movitel.co.mz;; 7) DOMAIN=tmcel.mz;; 0) return;;
  *) printf '%sOpção inválida.%s\n' "$RED" "$RESET"; return;;
 esac
 printf '%sDomínio selecionado: %s%s\n' "$GREEN" "$DOMAIN" "$RESET"
 printf '\n=== DNS A ===\n'; dig +time=3 +tries=1 +short A "$DOMAIN"
 printf '\n=== DNS AAAA ===\n'; dig +time=3 +tries=1 +short AAAA "$DOMAIN"
 printf '\n=== Estado HTTP ===\n'; http_probe "$DOMAIN"
 printf '\n=== TLS/SNI (443) ===\n'
 timeout 10 openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>&1
}


# BUG HUNTER educativo: verificações não intrusivas para um único alvo autorizado.
bug_hunter(){
  ask_domain || return
  local host="$DOMAIN" file="$OUT/bug_hunter_${DOMAIN}_$(stamp).txt"
  local headers code https_code http_code tls dates server h
  printf '%s=== BUG HUNTER EDUCATIVO: %s ===%s\n' "$CYAN" "$host" "$RESET"
  {
    echo "STONA FINDER PRO — BUG HUNTER EDUCATIVO"
    echo "Alvo: $host"
    echo "Data: $(date)"
    echo "Escopo: verificações HTTP/TLS não intrusivas; não é um teste de penetração completo."
    echo
    echo "=== HTTPS / código HTTP ==="
    https_code="$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 4 --max-time 8 "https://$host/" 2>/dev/null || true)"
    [[ -n "$https_code" ]] || https_code=000
    echo "HTTPS: HTTP $https_code"
    echo
    echo "=== HTTP e redirecionamento para HTTPS ==="
    http_code="$(curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' --connect-timeout 4 --max-time 8 "http://$host/" 2>/dev/null || true)"
    [[ -n "$http_code" ]] || http_code="000"
    echo "HTTP: $http_code"
    case "$http_code" in
      "301 https://"*|"302 https://"*|"307 https://"*|"308 https://"*)
        echo "[OK] HTTP parece redirecionar para HTTPS.";;
      "000"*) echo "[INFO] Sem resposta HTTP; pode ser firewall, timeout ou serviço indisponível.";;
      *) echo "[REVISAR] Confirma manualmente se HTTP redireciona para HTTPS; respostas variam conforme o servidor.";;
    esac
    echo
    echo "=== Cabeçalhos de segurança ==="
    headers="$(curl -sS -I -L --max-redirs 3 --connect-timeout 4 --max-time 8 "https://$host/" 2>/dev/null || true)"
    for h in strict-transport-security content-security-policy x-content-type-options x-frame-options referrer-policy permissions-policy; do
      if printf '%s\n' "$headers" | grep -qi "^${h}:"; then
        printf '[PRESENTE] %s\n' "$h"
      else
        printf '[AUSENTE]  %s — verificar se é aplicável ao site\n' "$h"
      fi
    done
    echo
    echo "=== Cabeçalho Server (informativo) ==="
    server="$(printf '%s\n' "$headers" | awk 'BEGIN{IGNORECASE=1} /^server:/{sub(/^[^:]*:[[:space:]]*/,""); print; exit}')"
    echo "${server:-Não divulgado}"
    echo
    echo "=== Certificado TLS ==="
    timeout 12 openssl s_client -connect "${host}:443" -servername "$host" </dev/null 2>/dev/null |
      openssl x509 -noout -subject -issuer -dates -fingerprint -sha256 2>&1 || echo "Não foi possível obter certificado TLS."
    echo
    echo "=== Interpretação ==="
    echo "Cabeçalho ausente não significa automaticamente vulnerabilidade."
    echo "Confirma os resultados, considera o contexto da aplicação e testa apenas sistemas autorizados."
  } | tee "$file"
  printf '%sRelatório guardado: %s%s\n' "$GREEN" "$file" "$RESET"
}

# Gerador educativo CONNECT: restringido a nomes/IPs de laboratório locais.
connect_payload_generator(){
  local host port file choice custom_header payload
  printf '%s=== CONNECT PAYLOAD GENERATOR — LABORATÓRIO ===%s\n' "$MAGENTA" "$RESET"
  echo "Por segurança, este modo só gera modelos para alvos de laboratório:"
  echo "localhost, nomes .test/.example/.invalid ou IPs privados (RFC1918)."
  printf 'Host de laboratório (ex.: lab.example ou 192.168.1.10): '; read -r host
  host="${host,,}"
  printf 'Porta de destino [443]: '; read -r port; port="${port:-443}"
  [[ "$port" =~ ^[0-9]{1,5}$ ]] && ((port>=1 && port<=65535)) || { printf '%sPorta inválida.%s\n' "$RED" "$RESET"; return; }
  local lab_ok=0
  case "$host" in
    localhost|*.test|*.example|*.invalid) lab_ok=1;;
  esac
  if [[ "$host" =~ ^10\.([0-9]{1,3}\.){2}[0-9]{1,3}$ ||
        "$host" =~ ^192\.168\.([0-9]{1,3}\.)[0-9]{1,3}$ ||
        "$host" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\.([0-9]{1,3}\.)[0-9]{1,3}$ ||
        "$host" == "127.0.0.1" ]]; then lab_ok=1; fi
  if (( lab_ok == 0 )); then
    printf '%sAlvo recusado: usa um host local/privado ou um domínio reservado de laboratório (.test/.example/.invalid).%s\n' "$RED" "$RESET"
    return
  fi
  printf 'Adicionar cabeçalho X-Lab-Note? (s/n): '; read -r choice
  custom_header=""
  if [[ "${choice,,}" == "s" ]]; then
    printf 'Texto simples para X-Lab-Note (sem CR/LF): '; read -r custom_header
    custom_header="${custom_header//$'\r'/}"; custom_header="${custom_header//$'\n'/}"
  fi
  payload="CONNECT ${host}:${port} HTTP/1.1"$'\r\n'"Host: ${host}:${port}"$'\r\n'"Proxy-Connection: Keep-Alive"$'\r\n'
  [[ -n "$custom_header" ]] && payload+="X-Lab-Note: ${custom_header}"$'\r\n'
  payload+=$'\r\n'
  echo
  printf '%s--- MODELO CONNECT (CRLF representado como linhas HTTP) ---%s\n' "$GREEN" "$RESET"
  printf '%s' "$payload"
  file="$OUT/connect_lab_$(stamp).txt"
  printf '%s' "$payload" > "$file"
  printf '\n%sGuardado em: %s%s\n' "$GREEN" "$file" "$RESET"
  echo "Nota: gerar o texto não cria um túnel nem confirma que um proxy aceite CONNECT."
}

show_results(){ echo "Resultados guardados em $OUT"; ls -lt "$OUT" 2>/dev/null | head -30; }
while true; do
 banner
 printf '%s1)%s Encontrar subdomínios públicos\n' "$GREEN" "$RESET"
 printf '%s2)%s Verificar SNI / TLS / certificado\n' "$GREEN" "$RESET"
 printf '%s3)%s Verificar estado HTTP de um domínio\n' "$GREEN" "$RESET"
 printf '%s4)%s Verificar hosts de uma lista guardada (máx. 100)\n' "$GREEN" "$RESET"
 printf '%s5)%s Consultar DNS e endereços IP\n' "$GREEN" "$RESET"
 printf '%s6)%s Ver resultados guardados\n' "$GREEN" "$RESET"
 printf '%s7)%s Pesquisa complementar de subdomínios (lista curta)\n' "$GREEN" "$RESET"
 printf '%s8)%s Diagnóstico IP / latência / indícios de CDN\n' "$GREEN" "$RESET"
 printf '%s9)%s Catálogo de operadores Angola / Moçambique\n' "$GREEN" "$RESET"
 printf '%s10)%s BUG HUNTER educativo (HTTP/TLS/cabeçalhos)\n' "$MAGENTA" "$RESET"
 printf '%s11)%s CONNECT Payload Generator (laboratório local)\n' "$MAGENTA" "$RESET"
 printf '%s0)%s Sair\n\n' "$RED" "$RESET"
 printf '%sEscolha: %s' "$CYAN" "$RESET"; read -r op
 case "$op" in
  1) find_subdomains; pause;;
  2) tls_check; pause;;
  3) status_check; pause;;
  4) status_list; pause;;
  5) dns_check; pause;;
  6) show_results; pause;;
  7) wordlist_scan; pause;;
  8) network_diagnostics; pause;;
  9) operator_catalog; pause;;
  10) bug_hunter; pause;;
  11) connect_payload_generator; pause;;
  0) echo "STONA FINDER encerrado."; exit 0;;
  *) echo "Opção inválida."; pause;;
 esac
done
