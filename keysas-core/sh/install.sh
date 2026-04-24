#!/usr/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# (C) Copyright 2019-2022 Stephane Neveu
# (C) Copyright 2019-2022 Nicolas Bouchinet

set -o errexit -o nounset

HOME_KEYSAS_IN="/var/local/in"
readonly HOME_KEYSAS_IN

HOME_KEYSAS_TRANSIT="/var/local/transit"
readonly HOME_KEYSAS_TRANSIT

HOME_KEYSAS_OUT="/var/local/out"
readonly HOME_KEYSAS_OUT

HOME_KEYSAS_ADMIN="/home/keysas"
readonly HOME_KEYSAS_ADMIN

U_KEYSAS_IN="keysas-in"
readonly U_KEYSAS_IN

U_KEYSAS_OUT="keysas-out"
readonly U_KEYSAS_OUT

U_KEYSAS_TRANSIT="keysas-transit"
readonly U_KEYSAS_TRANSIT

U_KEYSAS_ANALYZE="keysas-analyze"
readonly U_KEYSAS_ANALYZE

U_KEYSAS_VIRUSTOTAL="keysas-virustotal"
readonly U_KEYSAS_VIRUSTOTAL

U_KEYSAS_ADMIN="keysas"
readonly U_KEYSAS_ADMIN

G_SUDO="sudo"
readonly G_SUDO

# Create keysas-in, keysas-transit and keysas-out users if necessary.
# keysas user is used for administration. Once enrolled by keysas-admin
# password authentication is disabled.
add_users() {
	if ! getent passwd ${U_KEYSAS_IN} >/dev/null; then
		useradd -r -M --shell /bin/false -d ${HOME_KEYSAS_IN} ${U_KEYSAS_IN}
		install -d -m 0750 -o ${U_KEYSAS_IN} -g ${U_KEYSAS_IN} ${HOME_KEYSAS_IN}
	fi
	if ! getent passwd ${U_KEYSAS_TRANSIT} >/dev/null; then
		useradd -r -M --shell /bin/false -d ${HOME_KEYSAS_TRANSIT} -G ${U_KEYSAS_IN} ${U_KEYSAS_TRANSIT}
		install -d -m 0750 -o ${U_KEYSAS_TRANSIT} -g ${U_KEYSAS_TRANSIT} ${HOME_KEYSAS_TRANSIT}
	fi
	if ! getent passwd ${U_KEYSAS_OUT} >/dev/null; then
		useradd -r -M --shell /bin/false -d ${HOME_KEYSAS_OUT} -G ${U_KEYSAS_TRANSIT} ${U_KEYSAS_OUT}
		install -d -m 0750 -o ${U_KEYSAS_OUT} -g ${U_KEYSAS_OUT} ${HOME_KEYSAS_OUT}
	fi
	if ! getent passwd ${U_KEYSAS_ANALYZE} >/dev/null; then
		useradd -r -M --shell /bin/false ${U_KEYSAS_ANALYZE}
	fi
	if ! getent passwd ${U_KEYSAS_VIRUSTOTAL} >/dev/null; then
		useradd -r -M --shell /bin/false ${U_KEYSAS_VIRUSTOTAL}
	fi
	if ! getent passwd ${U_KEYSAS_ADMIN} >/dev/null; then
		useradd -M --shell /bin/bash -d ${HOME_KEYSAS_ADMIN} -U ${U_KEYSAS_ADMIN} -G ${G_SUDO} -p '$6$oFhHZhscHfd1n15H$NvVSbktCLhVe9dnMJarTDNKhctbJ/B9GZoApyH7Lp1s2EjfBsLWUJM/QsdgCeGr62BxohWbQB3Qwm3rimH4O01'
		install -d -m 0750 -o ${U_KEYSAS_ADMIN} -g ${U_KEYSAS_ADMIN} ${HOME_KEYSAS_ADMIN}
	fi
}

# Install ELF binaries in /usr/bin/.
install_bin() {
	if [ -d "/usr/bin" ]; then
		if [ -f "../bin/keysas-in" ]; then
			install -v -o ${U_KEYSAS_IN} -g ${U_KEYSAS_IN} -m 0500 ../bin/keysas-in /usr/bin/
		else
			echo "Binary ../bin/keysas-in cannot be found !"
		fi
	fi
	if [ -d "/usr/bin" ]; then
		if [ -f "../bin/keysas-transit" ]; then
			install -v -o ${U_KEYSAS_TRANSIT} -g ${U_KEYSAS_TRANSIT} -m 0500 ../bin/keysas-transit /usr/bin/
		else
			echo "Binary ../bin/keysas-transit cannot be found !"
		fi
	fi
	if [ -d "/usr/bin" ]; then
		if [ -f "../bin/keysas-out" ]; then
			install -v -o ${U_KEYSAS_OUT} -g ${U_KEYSAS_OUT} -m 0500 ../bin/keysas-out /usr/bin/
		else
			echo "Binary ../bin/keysas-out cannot be found !"
		fi
	fi
	if [ -d "/usr/bin" ]; then
		if [ -f "../bin/keysas-analyze" ]; then
			install -v -o ${U_KEYSAS_ANALYZE} -g ${U_KEYSAS_ANALYZE} -m 0500 ../bin/keysas-analyze /usr/bin/
		else
			echo "Binary ../bin/keysas-analyze cannot be found !"
		fi
	fi
	if [ -d "/usr/bin" ]; then
		if [ -f "../bin/keysas-virustotal" ]; then
			install -v -o ${U_KEYSAS_VIRUSTOTAL} -g ${U_KEYSAS_VIRUSTOTAL} -m 0500 ../bin/keysas-virustotal /usr/bin/
		else
			echo "Binary ../bin/keysas-virustotal cannot be found !"
		fi
	fi
}

# Install systemd units.
install_systemd_units() {
	if [ -d "/etc/systemd/system/" ]; then
		install -v -o root -g root -m 0644 debian/keysas.service /etc/systemd/system/keysas.service
		install -v -o root -g root -m 0644 debian/keysas-in.service /etc/systemd/system/keysas-in.service
		install -v -o root -g root -m 0644 debian/keysas-transit.service /etc/systemd/system/keysas-transit.service
		install -v -o root -g root -m 0644 debian/keysas-out.service /etc/systemd/system/keysas-out.service
		install -v -o root -g root -m 0644 debian/keysas-out-idle.service /etc/systemd/system/keysas-out-idle.service
		install -v -o root -g root -m 0644 debian/keysas-out-idle.timer /etc/systemd/system/keysas-out-idle.timer
		install -v -o root -g root -m 0644 debian/keysas-analyze.service /etc/systemd/system/keysas-analyze.service
		install -v -o root -g root -m 0644 debian/keysas-virustotal.service /etc/systemd/system/keysas-virustotal.service
		install -v -o root -g root -m 0644 debian/clamav-daemon.socket /etc/systemd/system/clamav-daemon.socket

		install -d -m 0750 -o root -g root /etc/systemd/system/keysas-in.service.d/
		if [ -f debian/keysas-in.security ]; then
			install -v -o root -g root -m 0644 debian/keysas-in.security /etc/systemd/system/keysas-in.service.d/security.conf
		fi
		install -d -m 0750 -o root -g root /etc/systemd/system/keysas-transit.service.d/
		if [ -f debian/keysas-transit.security ]; then
			install -v -o root -g root -m 0644 debian/keysas-transit.security /etc/systemd/system/keysas-transit.service.d/security.conf
		fi
		install -d -m 0750 -o root -g root /etc/systemd/system/keysas-out.service.d/
		if [ -f debian/keysas-out.security ]; then
			install -v -o root -g root -m 0644 debian/keysas-out.security /etc/systemd/system/keysas-out.service.d/security.conf
		fi
		install -d -m 0750 -o root -g root /etc/systemd/system/keysas-analyze.service.d/
		if [ -f debian/keysas-analyze.security ]; then
			install -v -o root -g root -m 0644 debian/keysas-analyze.security /etc/systemd/system/keysas-analyze.service.d/security.conf
		fi
		install -d -m 0750 -o root -g root /etc/systemd/system/keysas-virustotal.service.d/
		if [ -f debian/keysas-virustotal.security ]; then
			install -v -o root -g root -m 0644 debian/keysas-virustotal.security /etc/systemd/system/keysas-virustotal.service.d/security.conf
		fi
	else
		echo "Path /etc/systemd/system/ not found, this system isprobably not using systemd !"
	fi
}

# Install Keysas config files.
install_config() {
	if [ ! -d "/etc/keysas" ]; then
		echo "Creating /etc/keysas directory."
		install -d -m 0755 -o root -g root /etc/keysas
	fi
	if [ -d "/etc/keysas/" ]; then
		echo "Installing configuration files for keysas."
		install -v -o ${U_KEYSAS_IN} -g ${U_KEYSAS_IN} -m 0600 debian/keysas-in.default /etc/keysas/keysas-in.conf
		install -v -o ${U_KEYSAS_TRANSIT} -g ${U_KEYSAS_TRANSIT} -m 0600 debian/keysas-transit.default /etc/keysas/keysas-transit.conf
		install -v -o ${U_KEYSAS_OUT} -g ${U_KEYSAS_OUT} -m 0600 debian/keysas-out.default /etc/keysas/keysas-out.conf
		install -v -o ${U_KEYSAS_ANALYZE} -g ${U_KEYSAS_ANALYZE} -m 0600 debian/keysas-analyze.default /etc/keysas/keysas-analyze.conf
		install -v -o ${U_KEYSAS_VIRUSTOTAL} -g ${U_KEYSAS_VIRUSTOTAL} -m 0600 debian/keysas-virustotal.default /etc/keysas/keysas-virustotal.conf
	fi
	if [ -d "/etc/sudoers.d" ]; then
		install -v -o root -g root -m 0644 debian/keysas-sudoconfig /etc/sudoers.d/010_keysas
	fi
}

# Install apparmor profiles.
install_apparmor_profiles() {
	if [ -d "/etc/apparmor.d/" ]; then
		echo "Installing Apparmor policies:"
		install -v -o root -g root -m 0644 debian/usr.bin.keysas-in /etc/apparmor.d/usr.bin.keysas-in
		install -v -o root -g root -m 0644 debian/usr.bin.keysas-transit /etc/apparmor.d/usr.bin.keysas-transit
		install -v -o root -g root -m 0644 debian/usr.bin.keysas-out /etc/apparmor.d/usr.bin.keysas-out
		install -v -o root -g root -m 0644 debian/usr.sbin.clamd /etc/apparmor.d/local/usr.sbin.clamd
	else
		echo "WARNING: Directory /etc/apparmor.d/ not found ! Cannot install Apparmod policies..."
	fi
	if [ -x "/usr/sbin/apparmor_parser" ]; then
		echo "Applying Apparmor policies !"
		/usr/sbin/apparmor_parser -r /etc/apparmor.d/usr.bin.keysas-in
		/usr/sbin/apparmor_parser -r /etc/apparmor.d/usr.bin.keysas-transit
		/usr/sbin/apparmor_parser -r /etc/apparmor.d/usr.bin.keysas-out
		/usr/sbin/apparmor_parser -r /etc/apparmor.d/usr.sbin.clamd
	else
		echo "WARNING: Cannot find /usr/sbin/apparmor_parser !"
		echo "WARNING: Will not apply new Apparmor policies for keysas !"
	fi
}

# Set ACLs on directories.
set_acls() {
	if [ -d "${HOME_KEYSAS_IN}" ]; then
		setfacl -b ${HOME_KEYSAS_IN}
		setfacl -m u:clamav:rx,g:${U_KEYSAS_IN}:rwx ${HOME_KEYSAS_IN}
	fi
	if [ -d "${HOME_KEYSAS_TRANSIT}" ]; then
		setfacl -b ${HOME_KEYSAS_TRANSIT}
		setfacl -m g:${U_KEYSAS_TRANSIT}:rwx ${HOME_KEYSAS_TRANSIT}
	fi
	if [ -d "${HOME_KEYSAS_OUT}" ]; then
		setfacl -b ${HOME_KEYSAS_OUT}
		setfacl -m g:${U_KEYSAS_OUT}:rwx ${HOME_KEYSAS_OUT}
	fi
}

# Install Yara rules.
# On first install: create the directory and install the minimal index.yar.
# Always: apply targeted patches to upstream rules to fix systematic false positives.
# Patches are idempotent (safe to run multiple times) and surgical (no full-file duplication).
install_yara_rule() {
	if [ ! -d "/usr/share/keysas/" ]; then
		echo "Installing a minimal YARA index.yar in /usr/share/keysas/"
		install -d -m 0755 -o root -g root /usr/share/keysas/
		install -d -m 0755 -o root -g root /usr/share/keysas/rules
		install -v -m 0644 -o root -g root yara/index.yar /usr/share/keysas/rules/index.yar
	fi

	[ -d "/usr/share/keysas/rules" ] || return 0

	echo "Applying YARA false-positive patches..."

	# --- index.yar ---
	# Disable crypto_signatures: detects crypto constants (CRC32, SHA, MD5, AES S-boxes)
	# present in all software using TLS/crypto — zero detection value, 100% FP rate.
	INDEX="/usr/share/keysas/rules/index.yar"
	if [ -f "${INDEX}" ]; then
		sed -i \
			's|^include "\./crypto/crypto_signatures\.yar"|// crypto_signatures disabled: crypto constants in all TLS software — FP only\n// include "./crypto/crypto_signatures.yar"|' \
			"${INDEX}"
	fi

	# --- packer_compiler_signatures.yar ---
	# Make all PECheck helper rules private: they characterize PE structure (IsPE32, IsPE64,
	# IsDLL, HasOverlay, HasDigitalSignature, ImportTableIsBad, etc.) and are designed to be
	# used as conditions in other rules, not as standalone detections.
	# Making them private: they still work as conditions but no longer fire alone.
	PACKERS="/usr/share/keysas/rules/packers/packer_compiler_signatures.yar"
	if [ -f "${PACKERS}" ]; then
		sed -i \
			's/^rule \([A-Za-z_][A-Za-z0-9_]*\) : PECheck$/private rule \1 : PECheck/' \
			"${PACKERS}"
	fi

	# --- Maldoc_PDF.yar ---
	# Disable invalid_trailer_structure: triggers on all scanned PDFs (no xref table).
	# Disable multiple_versions: triggers on every incrementally-saved PDF (standard feature).
	# Both rules were commented by their own author as having no detection value.
	PDF_MALDOC="/usr/share/keysas/rules/maldocs/Maldoc_PDF.yar"
	if [ -f "${PDF_MALDOC}" ]; then
		python3 - "${PDF_MALDOC}" <<'PYEOF'
import sys, re

def disable_rule(content, rule_name, reason):
    """Wrap a YARA rule block in /* ... */ — idempotent."""
    # Skip if already disabled
    if f'// {rule_name} disabled' in content:
        return content
    # Match: rule declaration line up to the standalone closing brace
    # The closing } of a YARA rule is always on its own line (no indentation in these files)
    pattern = (
        r'(^rule ' + re.escape(rule_name) + r'(?:[ \t]*:[ \t]*\w+)*[ \t]*\n'
        r'\{(?:[^}]|\}(?!\n))*\}[ \t]*\n?)'
    )
    m = re.search(pattern, content, re.MULTILINE | re.DOTALL)
    if not m:
        print(f'  {rule_name}: not found (already patched or not present)')
        return content
    original = m.group(1)
    patched = f'// {rule_name} disabled: {reason}\n/*\n{original}*/\n'
    print(f'  {rule_name}: disabled')
    return content.replace(original, patched, 1)

path = sys.argv[1]
content = open(path).read()
content = disable_rule(content, 'invalid_trailer_structure',
    'triggers on scanned PDFs (no xref table) — high FP rate')
content = disable_rule(content, 'multiple_versions',
    'triggers on every incrementally-saved PDF (standard feature) — FP on all edited docs')
open(path, 'w').write(content)
PYEOF
	fi

	echo "YARA patches applied."
}

# Install external tools required by keysas-analyze.
# Non-fatal: missing tools reduce analysis capability but do not break keysas.
install_analyzer_tools() {
	echo "--- Installing keysas-analyze external tools ---"

	# binutils (strings) — usually present, ensure it is
	if ! command -v strings >/dev/null 2>&1; then
		apt-get install -y binutils || \
			echo "WARNING: binutils not installed. PE string analysis disabled."
	fi

	# oletools: olevba — Office document analysis
	# Use pipx for isolated install without --break-system-packages
	if ! command -v olevba >/dev/null 2>&1; then
		echo "Installing oletools..."
		apt-get install -y python3-oletools 2>/dev/null || \
		( apt-get install -y pipx 2>/dev/null && \
		  PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install oletools 2>/dev/null ) || \
			echo "WARNING: oletools not installed. Office analysis disabled."
	else
		echo "oletools already installed."
	fi

	# pdfid (Didier Stevens) — PDF analysis
	# peepdf is unmaintained and incompatible with Python 3.13+
	# pdfid is a pure-Python replacement installed via venv (no --break-system-packages needed)
	if ! command -v pdfid >/dev/null 2>&1; then
		echo "Installing pdfid..."
		if python3 -m venv /opt/pdfid-venv 2>/dev/null \
			&& /opt/pdfid-venv/bin/pip install pdfid 2>/dev/null; then
			printf '#!/bin/sh\nexec /opt/pdfid-venv/bin/python3 -m pdfid "$@"\n' \
				> /usr/local/bin/pdfid
			chmod +x /usr/local/bin/pdfid
			echo "pdfid installed."
		else
			echo "WARNING: pdfid not installed. PDF analysis disabled."
		fi
	else
		echo "pdfid already installed."
	fi

	# diec (Detect-It-Easy) — PE/executable analysis
	if ! command -v diec >/dev/null 2>&1; then
		echo "Installing diec (Detect-It-Easy)..."
		# Try apt first
		if apt-get install -y diec 2>/dev/null; then
			echo "diec installed via apt."
		else
			# Query GitHub API for latest release, use Debian 12 .deb (compatible with Debian 13)
			DIEC_ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
			DIEC_VER=$(curl -fsSL --max-time 10 \
				"https://api.github.com/repos/horsicq/DIE-engine/releases/latest" 2>/dev/null \
				| python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'])" 2>/dev/null \
				|| echo "3.10")
			DIEC_DEB="die_${DIEC_VER}_Debian_12_${DIEC_ARCH}.deb"
			DIEC_URL="https://github.com/horsicq/DIE-engine/releases/download/${DIEC_VER}/${DIEC_DEB}"
			TMP_DEB=$(mktemp /tmp/diec_XXXXXX.deb)
			echo "Downloading ${DIEC_DEB} from GitHub..."
			if curl -fsSL --max-time 120 "${DIEC_URL}" -o "${TMP_DEB}" 2>/dev/null \
				&& [ -s "${TMP_DEB}" ]; then
				dpkg -i "${TMP_DEB}" 2>/dev/null; apt-get install -f -y 2>/dev/null || true
				rm -f "${TMP_DEB}"
				if command -v diec >/dev/null 2>&1; then
					echo "diec installed."
				else
					echo "WARNING: diec install failed. PE analysis disabled."
					echo "         Manual: https://github.com/horsicq/DIE-engine/releases"
				fi
			else
				rm -f "${TMP_DEB}"
				echo "WARNING: Could not download diec (no internet or URL changed)."
				echo "         PE analysis disabled."
				echo "         Manual: https://github.com/horsicq/DIE-engine/releases"
			fi
		fi
	else
		echo "diec already installed."
	fi

	echo "--- Analyzer tools installation complete ---"
	echo "Tool status:"
	printf "  olevba  : "; command -v olevba  >/dev/null 2>&1 && echo "OK" || echo "MISSING (Office analysis disabled)"
	printf "  pdfid   : "; command -v pdfid   >/dev/null 2>&1 && echo "OK" || echo "MISSING (PDF analysis disabled)"
	printf "  diec    : "; command -v diec    >/dev/null 2>&1 && echo "OK" || echo "MISSING (PE entropy/packer analysis disabled)"
	printf "  strings : "; command -v strings >/dev/null 2>&1 && echo "OK" || echo "MISSING (PE string analysis disabled)"
}

# Enable systemd units.
enable_systemd() {
	echo "Reloading units..."
	systemctl stop clamav-daemon
	systemctl daemon-reload
	echo "Enabling keysas system in systemd..."
	systemctl enable clamav-daemon.socket
	systemctl enable keysas-in.service
	systemctl enable keysas-out.service
	systemctl enable keysas-out-idle.timer
	systemctl start keysas-out-idle.timer
	systemctl enable keysas-transit.service
	systemctl enable keysas-analyze.service
	systemctl enable keysas-virustotal.service
	systemctl enable keysas.service --now | true
	systemctl restart clamav-daemon
}

main() {
	# Call the above functions to perform the installation.
	add_users
	install_bin
	install_systemd_units
	install_config
	#install_apparmor_profiles
	install_analyzer_tools
	set_acls
	install_yara_rule
	enable_systemd

	# Now let's try to be more verbose for the end users
	cat <<-EOF
	  _                  _____       _      _          _
  o         o/                                                      
 <|>       /v                                                       
 / >      />                                                        
 \o__ __o/      o__  __o    o      o    __o__   o__ __o/      __o__ 
  |__ __|      /v      |>  <|>    <|>  />  \   /v     |      />  \  
  |      \    />      //   < >    < >  \o     />     / \     \o     
 <o>      \o  \o    o/      \o    o/    v\    \      \o/      v\    
  |        v\  v\  /v __o    v\  /v      <\    o      |        <\   
 / \        <\  <\/> __/>     <\/>  _\o__</    <\__  / \  _\o__</   
                               /                                    
                              o                                     
       Core                 __/>                                     
	
	EOF
	echo "Installation completed !"

	INGID=$(getent group ${U_KEYSAS_IN} | awk -F: '{printf "%d\n", $3}')
	readonly INGID

	OUTGID=$(getent group ${U_KEYSAS_OUT} | awk -F: '{printf "%d\n", $3}')
	readonly OUTGID

	cat <<-EOF
		-|>- You can now create new users belonging to group keysas-in
		     to be able to deposit files into /var/local/in/
		     sudo adduser  --home /var/local/in --gid ${INGID} untrusted_user
		-|>- You also need to create new users belonging to group keysas-out
		     to be able to retrieve files from /var/local/out/
		     sudo adduser  --home /var/local/out --gid ${OUTGID} trusted_user
	EOF
}

main "$@"
 
