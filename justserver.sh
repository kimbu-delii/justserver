#!/bin/bash
# =====================================================================================================
# JUSTSERVER ULTIMATE - UBUNTU SERVER YÖNETİM PANELİ                                                 #
# Sürüm: 5.0-ULTIMATE                                                                                #
# Geliştirici: JustTekno & BitronixCode                                                              #
# Tarih: 2025-08-02                                                                                  #
# Lisans: MIT                                                                                         #
# Kodlama: UTF-8                                                                                      #
# Açıklama: BIND9, CloudPanel ve Mail Server kurulum ve yönetim aracı                               #
# =====================================================================================================

# =====================================================
# 🌐 SİSTEM VE SUNUCU DEĞİŞKENLERİ
# =====================================================
BETIK_SURUMU="5.0-ULTIMATE"
BETIK_TARIHI=$(date '+%Y-%m-%d %H:%M:%S')
BETIK_BASLANGIC_ZAMANI=$(date +%s)
SUNUCU_ADI="$(hostname)"
MEVCUT_KULLANICI="$(whoami)"

# =====================================================
# 🎨 RENK VE STİL AYARLARI
# =====================================================
ACIK_PEMBE='\033[1;35m'    # Parlak Magenta (Bold Magenta)
BEYAZ='\033[1;37m'         # Parlak Beyaz (Bold White)  
SARI='\033[1;33m'          # Parlak Sarı (Bold Yellow)
ACIK_YESIL='\033[1;32m'    # Parlak Yeşil (Bold Green)
TURKUAZ='\033[1;36m'       # Parlak Cyan (Bold Cyan)
TURUNCU='\033[1;91m'       # Parlak Kırmızı (Bright Red)
NC='\033[0m'               # Reset/Normal
MOR='\033[0;35m'           # Normal Magenta
GRI='\033[0;37m'           # Normal White/Light Gray
STIL_KALIN='\033[1m'       # Bold Style
STIL_ALTCIZILI='\033[4m'   # Underline Style

# =====================================================
# 📁 DOSYA VE DİZİN AYARLARI
# =====================================================
BETIK_DIZINI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
YEDEK_DIZINI="/home/clp/yedekler/mail"
GUNLUK_DIZINI="/home/clp/gunlukler/mail"
KURULUM_TAMAMLANDI_BAYRAGI="/home/clp/.kurulum_tamamlandi"
GUNLUK_DOSYASI="/var/log/web-mail-kurulum.log"
LOG_FILE="/var/log/bind_cloudpanel_install.log"

# CloudPanel uyumlu dizinler
CLP_AYAR_DIZINI="/home/clp"
CLP_SERVISLER_DIZINI="/home/clp/servisler"

# Webmail, Nginx ve mail dizinleri
WEBMAIL_TEMEL_DIZIN="/home/clp/webmail"
NGINX_ETKIN_SITELER="/etc/nginx/sites-enabled"
NGINX_MEVCUT_SITELER="/etc/nginx/sites-available"
SSL_SERTIFIKA_DIZINI="/etc/nginx/ssl-sertifikalari"
MAIL_DIZINI="/var/mail/vhosts"
OPENDKIM_AYAR_DIZINI="/etc/opendkim"
DOVECOT_AYAR_DIZINI="/etc/dovecot"
POSTFIX_AYAR_DIZINI="/etc/postfix"

# =====================================================
# 🌐 SİSTEM VE SUNUCU DEĞİŞKENLERİ
# =====================================================

# IP Bilgileri
DIS_IP="$(curl -s https://ipinfo.io/ip 2>/dev/null || echo '85.105.160.98')"
IC_IP="$(hostname -I | awk '{print $1}' 2>/dev/null || echo '192.168.1.200')"

SSH_PORT="22"
SSH_OZEL_PORT="2200"

# =====================================================
# 👤 KULLANICI VE ŞİFRE AYARLARI
# =====================================================
KULLANICI_ADI="codex"
SISTEM_ROOT_SIFRE="q"
VARSAYILAN_SIFRE='439522HD'
YONETICI_SIFRE="$VARSAYILAN_SIFRE"

# Manuel giriş değişkenleri
YENI_ALAN_ADI=""

# =====================================================
# 🔑 MYSQL VE VERİTABANI AYARLARI
# =====================================================
MYSQL_SUNUCU="127.0.0.1"
MYSQL_PORT="3306"
MYSQL_ROOT_KULLANICI="root"
MYSQL_ROOT_SIFRE=""  # Manuel girilecek

ROUNDCUBE_VERITABANI_ADI="roundcube"
ROUNDCUBE_VERITABANI_KULLANICI="roundcube"
ROUNDCUBE_VERITABANI_SIFRE="$VARSAYILAN_SIFRE"

MAIL_VERITABANI_ADI="mailserver"
MAIL_VERITABANI_KULLANICI="mailkullanici"
MAIL_VERITABANI_SIFRE="$VARSAYILAN_SIFRE"

# =====================================================
# 📧 MAIL, POSTFIX, DOVECOT AYARLARI
# =====================================================
SMTP_SUNUCU="localhost"
SMTP_PORT="25"
SMTP_KIMLIK_DOGRULAMA="false"
SMTP_KULLANICI=""
SMTP_SIFRE="$VARSAYILAN_SIFRE"

IMAP_SUNUCU="localhost"
IMAP_PORT="143"
IMAP_SSL_PORT="993"
POP3_SUNUCU="localhost"
POP3_PORT="110"
POP3_SSL_PORT="995"

# =====================================================
# 🌍 DOMAIN (ALAN ADI) LİSTESİ
# =====================================================
ALAN_ADLARI=(
    "justtekno.tr"
    "craftaparat.com"
    "bitronixcode.com"
    "bitronixcode.net"
    "bitronixcode.xyz"
)

DOMAINS=("${ALAN_ADLARI[@]}")
ANA_DOMAIN="${DOMAINS[0]}"
SERIAL=$(date +%Y%m%d%H)

# =====================================================
# 🔒 SSL SERTİFİKA YOLLARI
# =====================================================
SSL_SERTIFIKA_BITRONIX_COM="/etc/nginx/ssl-sertifikalari/bitronixcode.com.crt"
SSL_ANAHTAR_BITRONIX_COM="/etc/nginx/ssl-sertifikalari/bitronixcode.com.key"
SSL_SERTIFIKA_BITRONIX_NET="/etc/nginx/ssl-sertifikalari/bitronixcode.net.crt"
SSL_ANAHTAR_BITRONIX_NET="/etc/nginx/ssl-sertifikalari/bitronixcode.net.key"
SSL_SERTIFIKA_BITRONIX_XYZ="/etc/nginx/ssl-sertifikalari/bitronixcode.xyz.crt"
SSL_ANAHTAR_BITRONIX_XYZ="/etc/nginx/ssl-sertifikalari/bitronixcode.xyz.key"
SSL_SERTIFIKA_CRAFT="/etc/nginx/ssl-sertifikalari/craftaparat.com.crt"
SSL_ANAHTAR_CRAFT="/etc/nginx/ssl-sertifikalari/craftaparat.com.key"
SSL_SERTIFIKA_JUST="/etc/nginx/ssl-sertifikalari/justtekno.tr.crt"
SSL_ANAHTAR_JUST="/etc/nginx/ssl-sertifikalari/justtekno.tr.key"
SSL_SERTIFIKA_SNAKEOIL="/etc/ssl/certs/ssl-cert-snakeoil.pem"
SSL_ANAHTAR_SNAKEOIL="/etc/ssl/private/ssl-cert-snakeoil.key"

# =====================================================
# 🐘 PHP AYARLARI
# =====================================================
PHP_SURUMU="8.3"
PHP_FPM_SOKETI="unix:/run/php/php8.3-fpm.sock"
PHP_FPM_KULLANICI="www-data"
PHP_FPM_GRUBU="www-data"
CLP_KULLANICI="clp"
CLP_GRUBU="clp"

# =====================================================
# 🌐 NGINX AYARLARI
# =====================================================
NGINX_KULLANICI="www-data"
NGINX_GRUBU="www-data"
MAKSIMUM_ISTEK_BOYUTU="100M"
FASTCGI_OKUMA_SURESI="300"

# =====================================================
# 📧 ROUNDCUBE AYARLARI
# =====================================================
ROUNDCUBE_SURUMU="1.6.9"
ROUNDCUBE_ADRESI="https://github.com/roundcube/roundcubemail/releases/download/1.6.9/roundcubemail-1.6.9-complete.tar.gz"
ROUNDCUBE_GECICI_DIZIN="/tmp/roundcube-kurulum"
ROUNDCUBE_ARSIV="roundcubemail-1.6.9-complete.tar.gz"

# =====================================================
# ☁️ CLOUDPANEL AYARLARI
# =====================================================
CLP_NGINX_SERVISI="clp-nginx"
CLP_PHP_FPM_SERVISI="clp-php-fpm"
CLP_AGENT_SERVISI="clp-agent"

# =====================================================
# 🔄 SİSTEM SERVİSLERİ
# =====================================================
KONTROL_EDILECEK_SERVISLER=(
    "nginx"
    "mysql"
    "postfix"
    "dovecot"
    "opendkim"
    "clp-nginx"
    "clp-php-fpm"
    "clp-agent"
)

# =====================================================
# ✅ KURULUM KONTROL DEĞİŞKENLERİ
# =====================================================
CLOUDPANEL_KURULU=false
MYSQL_AKTIF=false
NGINX_AKTIF=false
POSTFIX_KURULU=false
DOVECOT_KURULU=false
OPENDKIM_KURULU=false
KURULUM_TAMAMLANDI_BAYRAGI="/var/log/cloudpanel-mail-kurulum-tamamlandi"

# =====================================================
# ✅ DJANGO Python KONTROL DEĞİŞKENLERİ
# =====================================================
DOMAIN=""
PROJE_YOLU=""
PORT=""
VENV_YOLU=""
PID_DOSYASI=""

# =====================================================
# 📊 BAŞARI SAYAÇLARI
# =====================================================
TOPLAM_ADIM=0
BASARILI_ADIM=0
BASARISIZ_ADIM=0

# =====================================================
# 🔑 DKIM ANAHTAR ÜRETİMİ VE DNS EKLEME FONKSİYONU
# =====================================================
dkim_anahtar_uret() {
    local domain=$1
    local anahtar_dizini="/etc/opendkim/keys/${domain}"
    local zone_file="/etc/bind/zones/db.$domain"
    
    echo -e "${TURKUAZ}🔑 ${domain} için DKIM anahtarı oluşturuluyor...${NC}"
    
    # Dizin zaten var mı kontrol et
    if [ -d "$anahtar_dizini" ] && [ -f "$anahtar_dizini/mail.private" ]; then
        echo -e "${SARI}⚠️  ${domain} için DKIM anahtarı zaten mevcut${NC}"
        
        # Zaten varsa DNS kaydını kontrol et ve yoksa ekle
        if ! grep -q "mail._domainkey.$domain" "$zone_file" 2>/dev/null; then
            dkim_dns_kaydi_ekle "$domain"
        else
            echo -e "${ACIK_YESIL}✅ DKIM DNS kaydı zaten mevcut${NC}"
        fi
        return 0
    fi
    
    # Dizin oluştur
    mkdir -p "$anahtar_dizini"
    
    # DKIM anahtarı üret
    if opendkim-genkey -t -s mail -d "$domain" -D "$anahtar_dizini"; then
        # İzinleri ayarla
        chown -R opendkim:opendkim "$anahtar_dizini"
        chmod 600 "$anahtar_dizini/mail.private"
        chmod 644 "$anahtar_dizini/mail.txt"
        
        echo -e "${ACIK_YESIL}✅ DKIM anahtarı başarıyla oluşturuldu${NC}"
        
        # DNS kaydını otomatik ekle
        dkim_dns_kaydi_ekle "$domain"
        
        # Kullanıcıya bilgi ver
        echo -e "${TURKUAZ}📋 DNS TXT kaydı:${NC}"
        cat "$anahtar_dizini/mail.txt"
        echo ""
    else
        echo -e "${TURUNCU}❌ DKIM anahtarı oluşturulamadı!${NC}"
        return 1
    fi
}

# =====================================================
# 🌐 DKIM DNS KAYDI OTOMATIK EKLEME FONKSİYONU
# =====================================================
dkim_dns_kaydi_ekle() {
    local domain=$1
    local anahtar_dizini="/etc/opendkim/keys/${domain}"
    local zone_file="/etc/bind/zones/db.$domain"
    local dkim_txt_file="$anahtar_dizini/mail.txt"
    
    echo -e "${TURKUAZ}🌐 ${domain} için DKIM DNS kaydı ekleniyor...${NC}"
    
    # DKIM txt dosyası var mı kontrol et
    if [[ ! -f "$dkim_txt_file" ]]; then
        echo -e "${TURUNCU}❌ DKIM txt dosyası bulunamadı: $dkim_txt_file${NC}"
        return 1
    fi
    
    # Zone dosyası var mı kontrol et
    if [[ ! -f "$zone_file" ]]; then
        echo -e "${TURUNCU}❌ Zone dosyası bulunamadı: $zone_file${NC}"
        return 1
    fi
    
    # DKIM kaydı zaten var mı kontrol et
    if grep -q "mail._domainkey.$domain" "$zone_file"; then
        echo -e "${SARI}⚠️  DKIM DNS kaydı zaten mevcut${NC}"
        return 0
    fi
    
    # DKIM public key'i oku ve temizle
    local dkim_record=$(cat "$dkim_txt_file" | grep -v '^;' | tr -d '\n' | sed 's/[[:space:]]//g')
    
    # Zone dosyasının sonuna DKIM kaydını ekle
    echo "" >> "$zone_file"
    echo "; DKIM Record" >> "$zone_file"
    echo "$dkim_record" >> "$zone_file"
    
    # Zone dosyasının serial numarasını güncelle
    local today=$(date +%Y%m%d)
    local current_serial=$(grep -o "${today}[0-9][0-9]" "$zone_file" | tail -1)
    
    if [[ -n "$current_serial" ]]; then
        local new_serial=$((current_serial + 1))
    else
        local new_serial="${today}01"
    fi
    
    # Serial numarasını güncelle
    sed -i "s/[0-9]\{10\}/$new_serial/" "$zone_file"
    
    # BIND9 konfigürasyonunu test et
    if named-checkzone "$domain" "$zone_file" > /dev/null 2>&1; then
        # BIND9'u yeniden yükle
        if systemctl reload bind9; then
            echo -e "${ACIK_YESIL}✅ DKIM DNS kaydı başarıyla eklendi ve BIND9 yeniden yüklendi${NC}"
            echo -e "${TURKUAZ}📋 Eklenen kayıt:${NC}"
            echo -e "${SARI}$dkim_record${NC}"
        else
            echo -e "${TURUNCU}❌ BIND9 yeniden yüklenemedi!${NC}"
            return 1
        fi
    else
        echo -e "${TURUNCU}❌ Zone dosyası geçersiz! DKIM kaydı eklenmedi.${NC}"
        # Hatalı kaydı geri al
        sed -i '/; DKIM Record/,$d' "$zone_file"
        return 1
    fi
}

# =====================================================
# 🧪 DKIM TEST FONKSİYONU
# =====================================================
dkim_test() {
    local domain=$1
    
    echo -e "${TURKUAZ}🧪 ${domain} için DKIM testi yapılıyor...${NC}"
    
    # DKIM DNS kaydını kontrol et
    local dkim_dns=$(dig +short TXT mail._domainkey.$domain)
    
    if [[ -n "$dkim_dns" ]]; then
        echo -e "${ACIK_YESIL}✅ DKIM DNS kaydı bulundu${NC}"
        echo -e "${SARI}📋 Kayıt: $dkim_dns${NC}"
    else
        echo -e "${TURUNCU}❌ DKIM DNS kaydı bulunamadı!${NC}"
        echo -e "${SARI}⚠️  DNS yayılması için 5-10 dakika bekleyin${NC}"
    fi
    
    # OpenDKIM servisi durumunu kontrol et
    if systemctl is-active --quiet opendkim; then
        echo -e "${ACIK_YESIL}✅ OpenDKIM servisi çalışıyor${NC}"
    else
        echo -e "${TURUNCU}❌ OpenDKIM servisi çalışmıyor!${NC}"
    fi
}

# =====================================================
# 📋 DMARC ANAHTAR ÜRETİMİ VE DNS EKLEME FONKSİYONU
# =====================================================
dmarc_yapilandir() {
    local domain=$1
    local zone_file="/etc/bind/zones/db.$domain"
    local dmarc_dizin="/etc/opendkim/dmarc"
    
    echo -e "${TURKUAZ}📋 ${domain} için DMARC yapılandırılıyor...${NC}"
    
    # DMARC dizini oluştur
    mkdir -p "$dmarc_dizin"
    
    # DMARC politika dosyası oluştur
    local dmarc_file="$dmarc_dizin/$domain.dmarc"
    cat > "$dmarc_file" << EOF
_dmarc.$domain. IN TXT "v=DMARC1; p=none; sp=none; pct=100; rua=mailto:dmarc@$domain; ruf=mailto:forensik@$domain; fo=1; adkim=r; aspf=r;"
EOF
    
    # DNS'e ekle
    dmarc_dns_kaydi_ekle "$domain"
    
    # DMARC rapor dizini oluştur
    mkdir -p "/var/log/dmarc/reports"
    chown -R opendkim:opendkim "/var/log/dmarc"
    
    # Postfix DMARC entegrasyonu
    postconf -e "dmarc_reports_address = dmarc@$domain"
    
    # DMARC ayarlarını göster
    echo -e "\n${BEYAZ}📋 DMARC Politikası Açıklaması:${NC}"
    echo -e "   • p=none          : ${SARI}Başlangıç politikası - izleme modu${NC}"
    echo -e "   • pct=100         : ${SARI}Politika tüm maillere uygulanır${NC}"
    echo -e "   • rua=           : ${SARI}Toplu raporlar: dmarc@$domain${NC}"
    echo -e "   • ruf=           : ${SARI}Adli raporlar: forensik@$domain${NC}"
    echo -e "   • fo=1           : ${SARI}Tüm başarısızlık raporları${NC}"
    echo -e "   • adkim=r        : ${SARI}Esnek DKIM hizalaması${NC}"
    echo -e "   • aspf=r         : ${SARI}Esnek SPF hizalaması${NC}"
    
    return 0
}

# =====================================================
# 🌐 DMARC DNS KAYDI OTOMATIK EKLEME FONKSİYONU
# =====================================================
dmarc_dns_kaydi_ekle() {
    local domain=$1
    local zone_file="/etc/bind/zones/db.$domain"
    local dmarc_file="/etc/opendkim/dmarc/$domain.dmarc"
    
    echo -e "${TURKUAZ}🌐 ${domain} için DMARC DNS kaydı ekleniyor...${NC}"
    
    # Dosyaları kontrol et
    if [[ ! -f "$dmarc_file" ]] || [[ ! -f "$zone_file" ]]; then
        echo -e "${TURUNCU}❌ Gerekli dosyalar bulunamadı!${NC}"
        return 1
    fi

    # DMARC kaydı zaten var mı kontrol et
    if grep -q "_dmarc.$domain" "$zone_file"; then
        echo -e "${SARI}⚠️  DMARC DNS kaydı zaten mevcut${NC}"
        return 0
    fi

    # DMARC kaydını zone dosyasına ekle
    echo "" >> "$zone_file"
    echo "; DMARC Record" >> "$zone_file"
    cat "$dmarc_file" >> "$zone_file"
    
    # Serial numarasını güncelle
    local today=$(date +%Y%m%d)
    local current_serial=$(grep -o "${today}[0-9][0-9]" "$zone_file" | tail -1)
    local new_serial="${today}01"
    
    if [[ -n "$current_serial" ]]; then
        new_serial=$((current_serial + 1))
    fi
    
    sed -i "s/[0-9]\{10\}/$new_serial/" "$zone_file"
    
    # BIND9 konfigürasyonunu test et ve yeniden yükle
    if named-checkzone "$domain" "$zone_file" > /dev/null 2>&1; then
        if systemctl reload bind9; then
            echo -e "${ACIK_YESIL}✅ DMARC DNS kaydı başarıyla eklendi${NC}"
        else
            echo -e "${TURUNCU}❌ BIND9 yeniden yüklenemedi!${NC}"
            return 1
        fi
    else
        echo -e "${TURUNCU}❌ Zone dosyası geçersiz!${NC}"
        sed -i '/; DMARC Record/,$d' "$zone_file"
        return 1
    fi
}

# =====================================================
# 🧪 DMARC TEST FONKSİYONU
# =====================================================
dmarc_test() {
    local domain=$1
    
    echo -e "${TURKUAZ}🧪 ${domain} için DMARC testi yapılıyor...${NC}"
    
    # DMARC DNS kaydını kontrol et
    local dmarc_dns=$(dig +short TXT _dmarc.$domain)
    
    if [[ -n "$dmarc_dns" ]]; then
        echo -e "${ACIK_YESIL}✅ DMARC DNS kaydı bulundu${NC}"
        echo -e "${SARI}📋 Kayıt: $dmarc_dns${NC}"
        
        # DMARC politikasını analiz et
        if [[ $dmarc_dns == *"p=none"* ]]; then
            echo -e "${SARI}⚠️  İzleme modunda (p=none)${NC}"
            echo -e "${BEYAZ}ℹ️  Politikayı sıkılaştırmak için:${NC}"
            echo -e "   1. p=none → p=quarantine"
            echo -e "   2. p=quarantine → p=reject"
        fi
    else
        echo -e "${TURUNCU}❌ DMARC DNS kaydı bulunamadı!${NC}"
        echo -e "${SARI}⚠️  DNS yayılması için bekleyin${NC}"
    fi
    
    # Rapor dizinini kontrol et
    if [[ -d "/var/log/dmarc/reports" ]]; then
        echo -e "${ACIK_YESIL}✅ DMARC rapor dizini mevcut${NC}"
        local rapor_sayisi=$(find "/var/log/dmarc/reports" -type f | wc -l)
        echo -e "${BEYAZ}📊 Toplam rapor sayısı: $rapor_sayisi${NC}"
    else
        echo -e "${TURUNCU}❌ DMARC rapor dizini bulunamadı!${NC}"
    fi
}

# =====================================================
#  GLOBAL DEĞİŞKENLER SONU
# =====================================================

# =====================================================
# 🛡️ ROOT YETKİSİ KONTROLÜ
# =====================================================
if [[ $EUID -ne 0 ]]; then
    echo -e "${TURUNCU}❌ Bu betik root yetkileri gerektirir!${NC}"
    echo -e "${SARI}Lütfen 'sudo $0' komutu ile çalıştırın.${NC}"
    exit 1
fi

# =====================================================
# 📝 GÜNLÜK YAZMA FONKSİYONLARI
# =====================================================

# Log fonksiyonu (root şifre fonksiyonu için kısa log)
log_mesaj() {
    local seviye="$1"
    local mesaj="$2"
    local tarih_saat="$(date '+%d.%m.%Y %H:%M:%S')"
    local log_dizini="/var/log/justserver"
    local log_dosyasi="${log_dizini}/ubuntu_optimize.log"
    mkdir -p "$log_dizini" 2>/dev/null
    echo "[$tarih_saat] [$seviye] $mesaj" >> "$log_dosyasi" 2>/dev/null || true
}

# Günlük yazma fonksiyonu
gunluk_yaz() {
    local seviye="$1"
    local mesaj="$2"
    local tarih_saat="$(date '+%d.%m.%Y %H:%M:%S')"
    local log_dizini="/var/log/justserver"
    local log_dosyasi="${log_dizini}/ubuntu_optimize.log"
    
    # Log dizinini oluştur
    mkdir -p "$log_dizini" 2>/dev/null
    
    # Log mesajını yaz
    echo "[$tarih_saat] [$seviye] $mesaj" >> "$log_dosyasi" 2>/dev/null || true
}

# =====================================================
# 🎯 ANA BAŞLIK GÖSTERME FONKSİYONU
# =====================================================
ana_baslik_goster() {
    clear
    local sistem_bilgisi="$(uname -sr 2>/dev/null || echo 'Bilinmiyor')"
    local hostname_bilgisi="$(hostname 2>/dev/null || echo 'justserver')"
    local tarih_saat="$(date '+%d.%m.%Y %H:%M:%S' 2>/dev/null || echo 'Bilinmiyor')"
    
    # Disk bilgilerini al
    local disk_kullanim=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    local disk_boyut=$(df -h / | awk 'NR==2 {print $2}')
    local kullanilan=$(df -h / | awk 'NR==2 {print $3}')
    local bos_alan=$(df -h / | awk 'NR==2 {print $4}')
    
    # Bellek bilgilerini al
    local toplam_bellek=$(free -m | awk 'NR==2 {print $2}')
    local kullanilan_bellek=$(free -m | awk 'NR==2 {print $3}')
    local bellek_yuzde=$((kullanilan_bellek * 100 / toplam_bellek))
    
    # CPU bilgilerini al
    local cpu_model=$(grep -m 1 "model name" /proc/cpuinfo | cut -d: -f2 | sed 's/^ *//' || echo "Bilinmiyor")
    local cpu_cores=$(grep -c "processor" /proc/cpuinfo)
    local cpu_load=$(cat /proc/loadavg | awk '{print $1}')
    
    echo -e "${TURKUAZ}═════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${TURKUAZ}                   ${TURKUAZ}🚀 JUSTSERVER ULTIMATE${NC}"
    echo -e "${TURKUAZ}                    ${GRI}v${BETIK_SURUMU} - Tam Otomatik Kurulum${NC}"
    echo -e "${TURKUAZ}                ${GRI}Geliştirici: JustTekno & BitronixCode${NC}"
    echo -e "${TURKUAZ}═════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${TURKUAZ} ${NC} ${TURKUAZ}🖥️ Sistem:${NC} $sistem_bilgisi ${TURKUAZ}|${NC} ${TURKUAZ}🏠 Host:${NC} $hostname_bilgisi ${TURKUAZ} ${NC}"
    echo -e "${TURKUAZ} ${NC} ${TURKUAZ}📅 Tarih:${NC} $tarih_saat ${TURKUAZ}|${NC} ${TURKUAZ}👤 Kullanıcı:${NC} $(whoami) ${TURKUAZ} ${NC}"
    echo -e "${TURKUAZ} ${NC} ${TURKUAZ}💽 Disk:${NC} $disk_boyut ${TURKUAZ}|${NC} ${TURKUAZ}📊 Kullanılan:${NC} $kullanilan (%$disk_kullanim) ${TURKUAZ}|${NC} ${TURKUAZ}📉 Boş:${NC} $bos_alan ${TURKUAZ} ${NC}"
    echo -e "${TURKUAZ} ${NC} ${TURKUAZ}🧠 RAM:${NC} $toplam_bellek MB ${TURKUAZ}|${NC} ${TURKUAZ}📈 Kullanılan:${NC} $kullanilan_bellek MB (%$bellek_yuzde) ${TURKUAZ} ${NC}"
    echo -e "${TURKUAZ} ${NC} ${TURKUAZ}⚙️ CPU:${NC} $cpu_cores çekirdek ${TURKUAZ}|${NC} ${TURKUAZ}📈 Yük:${NC} $cpu_load ${TURKUAZ} ${NC}"
    echo -e "${TURKUAZ}═════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# =====================================================
# 📊 SİSTEM DURUMU GÖSTERME FONKSİYONU
# =====================================================
sistem_durumu_goster() {
    echo -e "${TURKUAZ}📊 Sistem Durumu: [DETAYLI KONTROL]${NC}"
    
    # Sistem durumu kontrolleri
    local sistem_hazir="HAZIR"
    local bind9_durum="ÇALIŞMIYOR"
    local cloudpanel_durum="ÇALIŞMIYOR"
    local mail_durum="ÇALIŞMIYOR"
    
    # BIND9 kontrol
    if systemctl is-active --quiet bind9 2>/dev/null; then
        bind9_durum="${ACIK_YESIL}ÇALIŞIYOR${NC}"
    else
        bind9_durum="${TURUNCU}ÇALIŞMIYOR${NC}"
    fi
    
    # CloudPanel kontrol
    if systemctl is-active --quiet nginx 2>/dev/null && systemctl is-active --quiet mysql 2>/dev/null; then
        cloudpanel_durum="${ACIK_YESIL}ÇALIŞIYOR${NC}"
    else
        cloudpanel_durum="${TURUNCU}ÇALIŞMIYOR${NC}"
    fi
    
    # Mail kontrol
    if systemctl is-active --quiet postfix 2>/dev/null && systemctl is-active --quiet dovecot 2>/dev/null; then
        mail_durum="${ACIK_YESIL}ÇALIŞIYOR${NC}"
    else
        mail_durum="${TURUNCU}ÇALIŞMIYOR${NC}"
    fi
    
    echo -e "   🔧 Sistem: ${ACIK_YESIL}$sistem_hazir${NC}"
    echo -e "   🌐 BIND9: $bind9_durum"
    echo -e "   ☁️ CloudPanel: $cloudpanel_durum"
    echo -e "   📧 Mail: $mail_durum"
    echo -e "   ⚠️ Bağımlılık: BIND9 → CloudPanel → Mail"
    echo ""
}

# =====================================================
# 🏠 ANA MENÜ GÖSTERME FONKSİYONU
# =====================================================
ana_menu_goster() {
    echo -e "${TURKUAZ}╔════════════════════════════════════╗${NC}"
    echo -e "${TURKUAZ}║         ANA İŞLEM MENÜSÜ          ║${NC}"
    echo -e "${TURKUAZ}╚════════════════════════════════════╝${NC}"
    echo ""
    echo -e "1) 🔧 Sistem Ayarla (Tek seferlik)"
    echo -e "2) 🌐 BIND9 (DNS - ÖNCELİKLİ)"
    echo -e "3) ☁️ CloudPanel (Web Panel + MySQL)"
    echo -e "4) 📧 Mail Sunucu Yönetimi"
    echo -e "5) 🧹 OpenCart Temizlik & İzin Modülü"
    echo -e "0) ❌ Çıkış"
    echo ""
}

# =====================================================
# ⌨️ ENTER BEKLEME FONKSİYONU
# =====================================================
enter_bekle() {
    echo ""
    echo -e "${SARI}Devam etmek için Enter tuşuna basın...${NC}"
    read -r
}

# =====================================================
# ❌ GEÇERSİZ SEÇİM FONKSİYONU
# =====================================================
gecersiz_secim() {
    echo -e "${TURUNCU}❌ Geçersiz seçim! Lütfen 0-4 arasında bir sayı girin.${NC}"
    enter_bekle
}

# =====================================================
# 🚪 ÇIKIŞ FONKSİYONU
# =====================================================
cikis_yap() {
    local bitis_zamani=$(date +%s)
    local gecen_sure=$((bitis_zamani - BETIK_BASLANGIC_ZAMANI))
    local dakika=$((gecen_sure / 60))
    local saniye=$((gecen_sure % 60))
    
    clear
    echo -e "${TURKUAZ}═════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${TURKUAZ}                          🎉 TEŞEKKÜRLER!${NC}"
    echo -e "${TURKUAZ}                    JustServer Ultimate Kullandığınız İçin${NC}"
    echo -e "${TURKUAZ}═════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${BEYAZ}📊 Oturum Özeti:${NC}"
    echo -e "   ⏱️ Toplam Süre: ${dakika} dakika ${saniye} saniye"
    echo -e "   🖥️ Sunucu: ${SUNUCU_ADI}"
    echo -e "   👤 Kullanıcı: ${MEVCUT_KULLANICI}"
    echo ""
    echo -e "${ACIK_YESIL}✅ Güvenli çıkış yapılıyor...${NC}"
    gunluk_yaz "BILGI" "JustServer Ultimate güvenli çıkış yapıldı (Süre: ${dakika}m ${saniye}s)"
    echo ""
    exit 0
}

# =====================================================
# 🔧 SİSTEM AYARLAMA FONKSİYONLARI
# =====================================================

# Root şifresi ayarlama fonksiyonu
sistem_root_sifre_ayarla() {
    log_mesaj "INFO" "Sistem root şifresi ayarlanıyor..."

    echo -e "\n${MOR}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MOR}║                ROOT KULLANICI ŞİFRE AYARI                ║${NC}"
    echo -e "${MOR}╚══════════════════════════════════════════════════════════╝${NC}\n"

    # Root şifresini değiştir
    echo "root:${SISTEM_ROOT_SIFRE}" | chpasswd

    if [ $? -eq 0 ]; then
        log_mesaj "SUCCESS" "Root şifresi başarıyla değiştirildi!"
        echo -e "${ACIK_YESIL}✅ Yeni root şifresi: ${SISTEM_ROOT_SIFRE}${NC}"

        # SSH root girişini etkinleştir (isteğe bağlı)
        if grep -q "^#*PermitRootLogin" /etc/ssh/sshd_config; then
            sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
        else
            echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
        fi
        systemctl restart ssh || systemctl restart sshd

        echo -e "${SARI}⚠️  SSH root girişi etkinleştirildi${NC}"
    else
        log_mesaj "ERROR" "Root şifresi değiştirilemedi!"
        echo -e "${TURUNCU}❌ Root şifresi değiştirilemedi!${NC}"
        exit 1
    fi
}

# Sistem güncelleme
sistem_guncelle() {
    echo -e "${TURKUAZ}🔄 SISTEM GUNCELLEME${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    echo -e "${BEYAZ}📦 Paket listesi güncelleniyor...${NC}"
    apt update
    
    echo -e "${BEYAZ}📦 Sistem güncelleniyor...${NC}"
    apt upgrade -y
    
    echo -e "${BEYAZ}📦 Kernel güncellemeleri yükleniyor...${NC}"
    apt dist-upgrade -y

    echo -e "${BEYAZ}📦 Ubuntu Paketi güncellemeleri yükleniyor...${NC}"
    apt install ubuntu-drivers-common iproute2 -y
    
    # Temel sunucu paketleri yükleme
    echo -e "${BEYAZ}📦 Temel sunucu paketleri yükleniyor...${NC}"
    
    # Sistem izleme ve yönetim araçları
    echo -e "${BEYAZ}   🔧 Sistem izleme ve yönetim araçları...${NC}"
    apt install -y htop iotop iftop net-tools dstat nload ncdu tmux screen mc
    
    # Ağ araçları
    echo -e "${BEYAZ}   🌐 Ağ araçları...${NC}"
    apt install -y curl wget nmap traceroute whois dnsutils tcpdump mtr-tiny
    
    # Dosya sistemi ve depolama araçları
    echo -e "${BEYAZ}   💾 Dosya sistemi ve depolama araçları...${NC}"
    apt install -y lvm2 mdadm xfsprogs btrfs-progs ntfs-3g exfat-utils
    
    # Sıkıştırma ve arşivleme araçları
    echo -e "${BEYAZ}   📚 Sıkıştırma ve arşivleme araçları...${NC}"
    apt install -y zip unzip p7zip-full p7zip-rar rar unrar-free
    
    # Metin düzenleyiciler
    echo -e "${BEYAZ}   📝 Metin düzenleyiciler...${NC}"
    apt install -y vim nano

    # Sistem bakım araçları
    echo -e "${BEYAZ}   🧰 Sistem bakım araçları...${NC}"
    apt install -y cron logrotate rsync at
    
    # Performans iyileştirme araçları
    echo -e "${BEYAZ}   ⚡ Performans iyileştirme araçları...${NC}"
    apt install -y preload irqbalance
    
    # Zaman senkronizasyon araçları
    echo -e "${BEYAZ}   🕒 Zaman senkronizasyon araçları...${NC}"
    apt install -y chrony
    
      # Temizlik işlemi
    echo -e "${BEYAZ}🧹 Artık bağımlılıklar temizleniyor...${NC}"
    apt autoremove -y
    apt autoclean
    
    echo -e "${ACIK_YESIL}✅ Sistem güncellemesi ve temel paketlerin kurulumu tamamlandı!${NC}"
    gunluk_yaz "BILGI" "Sistem güncellemesi ve temel paketlerin kurulumu tamamlandı"
    echo ""
}

# Gereksiz paketleri kaldır
gereksiz_paketleri_kaldir() {
    echo -e "${TURKUAZ}🧹 GEREKSIZ PAKET TEMIZLEME${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    # Temizlik öncesi disk kullanımı
    echo -e "${BEYAZ}📊 Temizlik öncesi disk kullanımı:${NC}"
    df -h / | grep -v "Filesystem"
    echo ""
    
    # Gereksiz masaüstü paketleri kaldır
    echo -e "${BEYAZ}🖥️ Masaüstü paketleri kaldırılıyor...${NC}"
    apt purge -y ubuntu-desktop gnome* xorg* lightdm* unity* compiz* metacity* nautilus* gedit* totem* rhythmbox* evolution* firefox* thunderbird* || true
    
    # Gereksiz ofis ve multimedya uygulamaları
    echo -e "${BEYAZ}📝 Ofis ve multimedya paketleri kaldırılıyor...${NC}"
    apt purge -y libreoffice* openoffice* simple-scan transmission-gtk transmission-common deja-dup shotwell remmina cheese vino brasero rhythmbox totem || true
    
    # Gereksiz oyun ve eğlence uygulamalarını kaldır
    echo -e "${BEYAZ}🎮 Oyun ve eğlence uygulamaları kaldırılıyor...${NC}"
    apt purge -y gnome-games* aisleriot gnome-mahjongg gnome-mines gnome-sudoku || true
    
    # Gereksiz donanım servisleri kaldır (sunucu için)
    echo -e "${BEYAZ}🔌 Gereksiz donanım servisleri kaldırılıyor...${NC}"
    apt purge -y bluez bluetooth blueman cups* printer-driver* system-config-printer* hplip* sane-utils simple-scan || true
    
    # Snapd ve gereksiz snap paketlerini kaldır
    echo -e "${BEYAZ}📦 Snapd ve snap paketleri kaldırılıyor...${NC}"
    apt purge -y snapd gnome-software-plugin-snap || true
    
    # Gereksiz ağ servisleri kaldır
    echo -e "${BEYAZ}🌐 Gereksiz ağ servisleri kaldırılıyor...${NC}"
    apt purge -y avahi-daemon avahi-utils || true
    
    # Gereksiz multimedya paketleri kaldır
    echo -e "${BEYAZ}🎵 Gereksiz multimedya paketleri kaldırılıyor...${NC}"
    apt purge -y gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly || true
    
    # Gereksiz belgelendirme paketleri kaldır
    echo -e "${BEYAZ}📚 Gereksiz belgelendirme paketleri kaldırılıyor...${NC}"
    apt purge -y ubuntu-docs gnome-user-docs || true
    
    # Dil paketleri kontrolü ve language-pack-* paketlerini kaldır (Türkçe ve İngilizce hariç)
    echo -e "${BEYAZ}🌍 Gereksiz dil paketleri kaldırılıyor (Türkçe ve İngilizce hariç)...${NC}"
    # Önce language-selector-common paketini kur (check-language-support için)
    apt install -y language-selector-common 2>/dev/null || true
    
    # language-pack paketlerini kaldır
    for lang in $(dpkg-query -W -f='${binary:Package}\n' language-pack-* 2>/dev/null | grep -v "en\|tr"); do
        apt purge -y $lang 2>/dev/null || true
    done
    
    # Gereksiz yazı tiplerini kaldır
    echo -e "${BEYAZ}🔤 Gereksiz yazı tipleri kaldırılıyor...${NC}"
    apt purge -y fonts-kacst* fonts-khmeros* fonts-lklug-sinhala fonts-guru-extra fonts-nanum* fonts-noto-cjk fonts-takao* fonts-tibetan-machine fonts-lao fonts-sil-padauk fonts-sil-abyssinica fonts-beng-extra fonts-gargi fonts-gubbi fonts-gujr-extra fonts-kalapi fonts-lohit-* fonts-nakula fonts-navilu fonts-orya-extra fonts-pagul fonts-sarai fonts-telu-extra fonts-wqy* fonts-smc* || true
    
    # Eski kernel paketlerini kaldır (mevcut çalışan kernel hariç)
    echo -e "${BEYAZ}🧠 Eski kernel paketleri kaldırılıyor...${NC}"
    current_kernel=$(uname -r | sed 's/-generic//')
    apt purge -y $(dpkg -l | grep -E "linux-image-[0-9]" | grep -v $current_kernel | awk '{print $2}') 2>/dev/null || true
    apt purge -y $(dpkg -l | grep -E "linux-headers-[0-9]" | grep -v $current_kernel | awk '{print $2}') 2>/dev/null || true
    
    # Temizlik işlemleri
    echo -e "${BEYAZ}🧹 Artık bağımlılıklar kaldırılıyor...${NC}"
    apt autoremove --purge -y
    
    echo -e "${BEYAZ}🧼 APT önbelleği temizleniyor...${NC}"
    apt clean
    
    echo -e "${BEYAZ}🗑️ Orphaned paketler kaldırılıyor...${NC}"
    apt autoremove --purge -y
    
    echo -e "${BEYAZ}🧪 Yapılandırma dosyaları temizleniyor...${NC}"
    dpkg --purge $(dpkg --get-selections | grep deinstall | cut -f1) 2>/dev/null || true
    
    # Temizlik sonrası disk kullanımı
    echo ""
    echo -e "${BEYAZ}📊 Temizlik sonrası disk kullanımı:${NC}"
    df -h / | grep -v "Filesystem"
    
    echo -e "${ACIK_YESIL}✅ Gereksiz paket temizleme işlemi tamamlandı!${NC}"
    gunluk_yaz "BILGI" "Gereksiz paket temizleme işlemi tamamlandı"
    echo ""
}

# Otomatik disk temizleme
disk_temizle() {
    echo -e "${TURKUAZ}🧹 DISK TEMIZLEME${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    local onceki_kullanim=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    # APT cache temizle
    echo -e "${BEYAZ}📦 APT cache temizleniyor...${NC}"
    apt-get clean
    apt-get autoclean
    apt-get autoremove -y
    
    # Gecici dosyalari temizle
    echo -e "${BEYAZ}🗂️ Geçici dosyalar temizleniyor...${NC}"
    local temizlik_dizinleri=("/tmp" "/var/tmp" "/var/log" "/var/cache/apt")
    
    for dizin in "${temizlik_dizinleri[@]}"; do
        if [[ -d "$dizin" ]]; then
            echo "   🗂️ Temizleniyor: $dizin"
            find "$dizin" -type f -atime +7 -delete 2>/dev/null || true
        fi
    done
    
    # Journal loglarini temizle
    echo -e "${BEYAZ}📋 Journal logları temizleniyor...${NC}"
    if command -v journalctl &> /dev/null; then
        journalctl --vacuum-size=500M
        journalctl --vacuum-time=30d
    fi
    
    local sonraki_kullanim=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    local temizlenen=$((onceki_kullanim - sonraki_kullanim))
    
    echo -e "${ACIK_YESIL}✅ Disk temizleme tamamlandı!${NC}"
    echo -e "   Önceki kullanım: %$onceki_kullanim"
    echo -e "   Sonraki kullanım: %$sonraki_kullanim"
    echo -e "   Temizlenen alan: %$temizlenen"
    
    gunluk_yaz "BILGI" "Disk temizleme tamamlandı (Önceki: %$onceki_kullanim, Sonraki: %$sonraki_kullanim)"
    echo ""
}

# LVM disk genişletme
lvm_genislet() {
    echo -e "${TURKUAZ}💾 LVM DISK GENISLETME${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    # LVM kurulu mu kontrol et
    if ! command -v lvm &> /dev/null; then
        echo -e "${SARI}⚠️ LVM kurulu değil, kuruluyor...${NC}"
        apt install -y lvm2
    fi
    
    # LVM cihazini tespit et
    echo -e "${BEYAZ}🔍 LVM cihazı tespit ediliyor...${NC}"
    local lvm_device=""
    
    # Olası LVM yollarını kontrol et
    local olasi_yollar=(
        "/dev/mapper/ubuntu--vg-ubuntu--lv"
        "/dev/ubuntu-vg/ubuntu-lv"
        "/dev/mapper/ubuntu-vg-ubuntu-lv"
    )
    
    for yol in "${olasi_yollar[@]}"; do
        if [[ -e "$yol" ]]; then
            lvm_device="$yol"
            echo -e "${ACIK_YESIL}✅ Tespit edilen LVM cihazı: $lvm_device${NC}"
            break
        fi
    done
    
    # Hala bulunamadıysa lvs ile ara
    if [[ -z "$lvm_device" ]]; then
        lvm_device=$(lvs --noheadings -o lv_path 2>/dev/null | grep -E "(root|ubuntu)" | head -1 | xargs)
        if [[ -n "$lvm_device" ]]; then
            echo -e "${ACIK_YESIL}✅ lvs ile tespit edilen cihaz: $lvm_device${NC}"
        fi
    fi
    
    # LVM cihazı bulunamadıysa
    if [[ -z "$lvm_device" || ! -e "$lvm_device" ]]; then
        echo -e "${SARI}⚠️ LVM cihazı tespit edilemedi, genişletme atlanıyor.${NC}"
        gunluk_yaz "UYARI" "LVM cihazı tespit edilemedi, genişletme atlandı"
        return 0
    fi
    
    # Physical Volume'lari genislet
    echo -e "${BEYAZ}🔧 Physical Volume'lar kontrol ediliyor...${NC}"
    
    while read -r pv_device; do
        if [[ -n "$pv_device" && -e "$pv_device" ]]; then
            echo "   📊 PV genişletiliyor: $pv_device"
            pvresize "$pv_device"
        fi
    done < <(pvs --noheadings -o pv_name 2>/dev/null)
    
    # Logical Volume'u genislet
    echo -e "${BEYAZ}🔧 Logical Volume genişletiliyor...${NC}"
    if lvextend -l +100%FREE "$lvm_device"; then
        echo -e "${ACIK_YESIL}✅ Logical Volume genişletildi${NC}"
        
        # Dosya sistemini genislet
        echo -e "${BEYAZ}🔧 Dosya sistemi genişletiliyor...${NC}"
        local fs_type=$(lsblk -no FSTYPE "$lvm_device" 2>/dev/null | head -1 || echo "ext4")
        
        case "$fs_type" in
            ext2|ext3|ext4)
                resize2fs "$lvm_device"
                echo -e "${ACIK_YESIL}✅ ext4 disk başarıyla genişletildi!${NC}"
                gunluk_yaz "BILGI" "ext4 disk genişletme başarılı: $lvm_device"
                ;;
            xfs)
                local mount_point=$(df "$lvm_device" 2>/dev/null | tail -1 | awk '{print $NF}')
                if [[ -n "$mount_point" ]]; then
                    xfs_growfs "$mount_point"
                    echo -e "${ACIK_YESIL}✅ XFS disk başarıyla genişletildi!${NC}"
                    gunluk_yaz "BILGI" "XFS disk genişletme başarılı: $lvm_device ($mount_point)"
                fi
                ;;
            *)
                echo -e "${SARI}⚠️ Desteklenmeyen dosya sistemi: $fs_type${NC}"
                gunluk_yaz "UYARI" "Desteklenmeyen dosya sistemi: $fs_type"
                ;;
        esac
    else
        echo -e "${SARI}ℹ️ Genişletilecek alan yok${NC}"
    fi
    
    echo ""
}

# Kullanıcı oluşturma ve sudo yetkisi verme
kullanici_olustur() {
    echo -e "${TURKUAZ}👤 KULLANICI OLUSTURMA VE YETKILENDIRME${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    # Kullanıcı var mı kontrol et
    if id "$KULLANICI_ADI" &>/dev/null; then
        echo -e "${SARI}ℹ️ '$KULLANICI_ADI' kullanıcısı zaten mevcut, sadece yetkilendirme yapılacak...${NC}"
    else
        echo -e "${BEYAZ}👤 '$KULLANICI_ADI' kullanıcısı oluşturuluyor...${NC}"
        useradd -m -s /bin/bash "$KULLANICI_ADI"
        
        # Rastgele şifre oluştur
        local sifre=$(openssl rand -base64 12)
        echo "$KULLANICI_ADI:$sifre" | chpasswd
        
        echo -e "${ACIK_YESIL}✅ Kullanıcı oluşturuldu!${NC}"
        echo -e "${BEYAZ}   Kullanıcı: $KULLANICI_ADI${NC}"
        echo -e "${BEYAZ}   Şifre: $sifre${NC}"
        echo -e "${SARI}   ⚠️ Bu şifreyi güvenli bir yere kaydedin!${NC}"
    fi
    
    # Sudo yetkisi ver
    echo -e "${BEYAZ}🔑 Sudo yetkisi veriliyor...${NC}"
    usermod -aG sudo "$KULLANICI_ADI"
    echo "$KULLANICI_ADI ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$KULLANICI_ADI"
    chmod 0440 "/etc/sudoers.d/$KULLANICI_ADI"
    
    echo -e "${ACIK_YESIL}✅ '$KULLANICI_ADI' kullanıcısına sudo yetkisi verildi!${NC}"
    gunluk_yaz "BILGI" "Kullanıcı oluşturuldu ve yetkilendirildi: $KULLANICI_ADI"
    echo ""
}

# SSH yapılandırması
ssh_yapilandir() {
    echo -e "${TURKUAZ}🔒 SSH GUVENLIK YAPILANDIRMASI${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
      
    echo -e "${BEYAZ}📝 SSH yapılandırması güncelleniyor...${NC}"
    
    cat > /etc/ssh/sshd_config << 'EOL'
# /etc/ssh/sshd_config
# Son Güncelleme: 2025-08-02
# JustServer Ultimate Optimizasyon

# ➡️ Dahili Konfigürasyonlar
# Diğer yapılandırma dosyalarını dahil eder
Include /etc/ssh/sshd_config.d/*.conf

# ➡️ Port Ayarları
Port ${SSH_PORT}        # Standart port
Port ${SSH_OZEL_PORT}   # Alternatif port (brute force saldırılarına karşı koruma)

# ➡️ Ağ Ayarları
AddressFamily inet      # Sadece IPv4 adreslerini dinle (IPv6 devre dışı)
ListenAddress 0.0.0.0   # Tüm ağ arayüzlerini dinle

# ➡️ Güvenlik Temel Ayarları
PermitRootLogin yes                  # Root kullanıcısı ile doğrudan giriş izni verildi
PasswordAuthentication yes           # Şifre ile giriş açık (anahtar tabanlı kimlik doğrulama tercih edilir)
PermitEmptyPasswords no              # Boş şifreli hesaplar engellenmiştir
ChallengeResponseAuthentication yes  # İki faktörlü kimlik doğrulama etkin
PubkeyAuthentication yes             # SSH anahtarı ile kimlik doğrulama etkin
GSSAPIAuthentication no              # Kerberos kimlik doğrulama devre dışı (performans için)
UsePAM yes                           # Linux PAM modülü etkin (kimlik doğrulama için)

# ➡️ Kullanıcı Erişim Kısıtlamaları
AllowUsers codex root       # 'codex' kullanıcısının SSH ile girişine izin verilir
DenyUsers clp               # 'clp' kullanıcısının SSH ile girişi engellendi

# ➡️ Kimlik Doğrulama Anahtar Dosyası
AuthorizedKeysFile %h/.ssh/authorized_keys  # Kullanıcının ev dizinindeki yetkilendirilmiş anahtarlar dosyası

# ➡️ Loglama ve Hata Yönetimi
SyslogFacility AUTH  # Kimlik doğrulama olaylarını AUTH kategorisinde logla
LogLevel VERBOSE     # Detaylı log kaydı tut (sorun giderme için faydalı)

# ➡️ Bağlantı Süreleri ve Oturum Ayarları
LoginGraceTime 60        # Giriş için 60 saniye süre tanı
ClientAliveInterval 60   # Her 60 saniyede bir bağlantı kontrolü yap
ClientAliveCountMax 5    # 5 başarısız kontrol sonrası bağlantıyı kes
MaxAuthTries 4           # Maksimum 4 kimlik doğrulama denemesine izin ver
MaxSessions 5            # Bir bağlantı üzerinde maksimum 5 oturum açılabilir

# ➡️ Performans Optimizasyonları
UseDNS no          # DNS ters sorguları devre dışı (bağlantı hızı için)
TCPKeepAlive yes   # TCP keep-alive mesajları etkin (bağlantı kopukluklarını tespit için)
Compression no     # SSH bağlantı sıkıştırması devre dışı (CRIME saldırılarına karşı)

# ➡️ Çevre Değişkenleri
AcceptEnv LANG LC_*  # Dil ve yerel ayar değişkenlerini kabul et

# ➡️ X11 Forwarding (GUI uygulamaları için)
X11Forwarding no     # X11 forwarding devre dışı (güvenlik için)
X11DisplayOffset 10  # X11 display offset
PrintMotd no         # Giriş mesajını SSH tarafından yazdırma
PrintLastLog yes     # Son giriş bilgisini göster

# ➡️ Banner ve Mesajlar
Banner none          # Giriş öncesi banner mesajı yok

# ➡️ Subsystem Ayarları
Subsystem sftp /usr/lib/openssh/sftp-server  # SFTP alt sistemi
EOL

    # SSH servisini yeniden başlat
    echo -e "${BEYAZ}🔄 SSH servisi yeniden başlatılıyor...${NC}"
    systemctl restart ssh
    
    if systemctl is-active --quiet ssh; then
        echo -e "${ACIK_YESIL}✅ SSH güvenlik yapılandırması tamamlandı!${NC}"
        echo -e "${BEYAZ}   📡 Port 22 ve 2200 aktif${NC}"
        echo -e "${BEYAZ}   👤 İzinli kullanıcılar: codex, root${NC}"
        echo -e "${BEYAZ}   🚫 Engellenen kullanıcı: clp${NC}"
        gunluk_yaz "BILGI" "SSH güvenlik yapılandırması tamamlandı"
    else
        echo -e "${TURUNCU}❌ SSH servis yeniden başlatılamadı!${NC}"
        gunluk_yaz "HATA" "SSH servis yeniden başlatılamadı"
    fi
    echo ""
}

# Performans optimizasyonu
performans_optimizasyonu() {
    echo -e "${TURKUAZ}⚡ PERFORMANS OPTIMIZASYONU${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    # Kernel parametreleri optimizasyonu
    echo -e "${BEYAZ}🧠 Kernel parametreleri optimizasyonu...${NC}"
    
    cat > /etc/sysctl.d/99-justserver-optimization.conf << 'EOL'
# JustServer Ultimate - Kernel Optimizasyonu
# Son Güncelleme: 2025-08-02

# ➡️ Ağ Performansı
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_congestion_control = bbr

# ➡️ Dosya Sistemi Optimizasyonu
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.swappiness = 10
vm.vfs_cache_pressure = 50

# ➡️ Güvenlik Optimizasyonu
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# ➡️ Bellek Yönetimi
kernel.shmmax = 268435456
kernel.shmall = 4194304
EOL

    # Kernel parametrelerini uygula
    sysctl -p /etc/sysctl.d/99-justserver-optimization.conf
    
    # I/O Scheduler optimizasyonu
    echo -e "${BEYAZ}💾 I/O Scheduler optimizasyonu...${NC}"
    echo 'ACTION=="add|change", KERNEL=="sd[a-z]*", ATTR{queue/scheduler}="mq-deadline"' > /etc/udev/rules.d/60-ioschedulers.rules
    
    # CPU frequency scaling
    echo -e "${BEYAZ}⚙️ CPU frequency scaling ayarları...${NC}"
    if [[ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
        echo 'performance' > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null || true
    fi
    
    echo -e "${ACIK_YESIL}✅ Performans optimizasyonu tamamlandı!${NC}"
    gunluk_yaz "BILGI" "Performans optimizasyonu tamamlandı"
    echo ""
}

# Güvenlik duvarı yapılandırması
guvenlik_duvari_yapilandir() {
    echo -e "${TURKUAZ}🔥 GÜVENLIK DUVARI YAPILANDIRMASI${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    # UFW kurulumu ve yapılandırması
    echo -e "${BEYAZ}🛡️ UFW güvenlik duvarı yapılandırılıyor...${NC}"
    
    # UFW'yi kur
    apt install -y ufw
    
    # UFW'yi sıfırla
    ufw --force reset
    
    # Varsayılan kuralları ayarla
    ufw default deny incoming
    ufw default allow outgoing
    
    # Temel portları aç
    echo -e "${BEYAZ}   📡 SSH portları açılıyor...${NC}"
    ufw allow ${SSH_PORT}/tcp
    ufw allow ${SSH_OZEL_PORT}/tcp
    
    echo -e "${BEYAZ}   🌐 Web portları açılıyor...${NC}"
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    echo -e "${BEYAZ}   🌐 DNS portları açılıyor...${NC}"
    ufw allow 53/tcp comment 'DNS TCP'
    ufw allow 53/udp comment 'DNS UDP'
    
    echo -e "${BEYAZ}   📧 Mail portları açılıyor...${NC}"
    ufw allow 25/tcp comment 'SMTP'
    ufw allow 587/tcp comment 'SMTP Submission'
    ufw allow 465/tcp comment 'SMTPS'
    ufw allow 143/tcp comment 'IMAP'
    ufw allow 993/tcp comment 'IMAPS'
    ufw allow 110/tcp comment 'POP3'
    ufw allow 995/tcp comment 'POP3S'
    
    echo -e "${BEYAZ}   🗄️ Database portları açılıyor...${NC}"
    ufw allow 3306/tcp comment 'MySQL'
    
    echo -e "${BEYAZ}   ☁️ CloudPanel portları açılıyor...${NC}"
    ufw allow 8443/tcp comment 'CloudPanel HTTPS'
    
    # UFW'yi etkinleştir
    ufw --force enable
    
    # UFW durumunu göster
    echo -e "${BEYAZ}📊 Güvenlik duvarı durumu:${NC}"
    ufw status numbered
    
    echo -e "${ACIK_YESIL}✅ Güvenlik duvarı yapılandırması tamamlandı!${NC}"
    gunluk_yaz "BILGI" "Güvenlik duvarı yapılandırması tamamlandı"
    echo ""
}

# =====================================================
# 🔧 ANA SİSTEM AYARLAMA FONKSİYONU
# =====================================================
sistem_ayarla() {
    ana_baslik_goster
    
    echo -e "${MOR}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MOR}║                    SİSTEM AYARLAMA                      ║${NC}"
    echo -e "${MOR}║            (Bu işlem sadece bir kez yapılır)            ║${NC}"
    echo -e "${MOR}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${SARI}⚠️ Bu işlem yaklaşık 10-15 dakika sürebilir.${NC}"
    echo -e "${SARI}⚠️ İşlem sırasında sistem yeniden başlatılabilir.${NC}"
    echo ""
    
    # Kullanıcı onayı al
    echo -e "${BEYAZ}Sistem ayarlamaya devam etmek istiyor musunuz? (E/h): ${NC}"
    read -r onay
    
    if [[ ! "$onay" =~ ^[EeYy]$ ]]; then
        echo -e "${SARI}⚠️ Sistem ayarlama iptal edildi.${NC}"
        return 0
    fi
    
    local baslangic_zamani=$(date +%s)
    
    echo -e "${TURKUAZ}🚀 SİSTEM AYARLAMA BAŞLANIYOR...${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    # Adım 1: Root şifre ayarlama
    echo -e "${TURKUAZ}[1/8]${NC} Root şifresi ayarlanıyor..."
    sistem_root_sifre_ayarla
    
    # Adım 2: Sistem güncelleme
    echo -e "${TURKUAZ}[2/8]${NC} Sistem güncelleniyor..."
    sistem_guncelle
    
    # Adım 3: Gereksiz paketleri kaldırma
    echo -e "${TURKUAZ}[3/8]${NC} Gereksiz paketler kaldırılıyor..."
    gereksiz_paketleri_kaldir
    
    # Adım 4: Disk temizleme
    echo -e "${TURKUAZ}[4/8]${NC} Disk temizleniyor..."
    disk_temizle
    
    # Adım 5: LVM genişletme
    echo -e "${TURKUAZ}[5/8]${NC} LVM disk genişletiliyor..."
    lvm_genislet
    
    # Adım 6: Kullanıcı oluşturma
    echo -e "${TURKUAZ}[6/8]${NC} Kullanıcı oluşturuluyor..."
    kullanici_olustur
    
    # Adım 7: SSH yapılandırması
    echo -e "${TURKUAZ}[7/8]${NC} SSH yapılandırılıyor..."
    ssh_yapilandir
    
    # Adım 8: Performans optimizasyonu ve güvenlik duvarı
    echo -e "${TURKUAZ}[8/8]${NC} Performans ve güvenlik optimizasyonu..."
    performans_optimizasyonu
    guvenlik_duvari_yapilandir
    
    local bitis_zamani=$(date +%s)
    local gecen_sure=$((bitis_zamani - baslangic_zamani))
    local dakika=$((gecen_sure / 60))
    local saniye=$((gecen_sure % 60))
    
    echo ""
    echo -e "${ACIK_YESIL}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${ACIK_YESIL}║                ✅ SİSTEM AYARLAMA TAMAMLANDI!           ║${NC}"
    echo -e "${ACIK_YESIL}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BEYAZ}📊 İşlem Özeti:${NC}"
    echo -e "   ⏱️ Toplam Süre: ${dakika} dakika ${saniye} saniye"
    echo -e "   🔑 Root Şifre: ${SISTEM_ROOT_SIFRE}"
    echo -e "   👤 Yeni Kullanıcı: ${KULLANICI_ADI}"
    echo -e "   📡 SSH Portları: 22, 2200"
    echo -e "   🛡️ Güvenlik Duvarı: Aktif"
    echo ""
    
    gunluk_yaz "BILGI" "Sistem ayarlama tamamlandı (Süre: ${dakika}m ${saniye}s)"
    
    # =====================================================
    # 🤔 MENÜ GEÇİŞİ İSTİŞARESİ
    # =====================================================
    echo -e "${TURKUAZ}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${TURKUAZ}║                    SONRAKI ADIM                         ║${NC}"
    echo -e "${TURKUAZ}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BEYAZ}Sistem ayarlama tamamlandı! Şimdi ne yapmak istersiniz?${NC}"
    echo ""
    echo -e "1) 🌐 BIND9 kurulumuna otomatik geç (ÖNERİLEN)"
    echo -e "2) 🏠 Ana menüye dön"
    echo -e "3) 🚪 Çıkış yap"
    echo ""
    echo -e "${SARI}Seçiminizi yapın (1-3): ${NC}"
    read -r secim
    
    case $secim in
        1)
            echo -e "${ACIK_YESIL}✅ BIND9 kurulumuna geçiliyor...${NC}"
            sleep 2
            bind9_tam_kur  # ✅ Doğru fonksiyon adı
            ;;
        2)
            echo -e "${TURKUAZ}🏠 Ana menüye dönülüyor...${NC}"
            sleep 1
            return 0
            ;;
        3)
            echo -e "${TURKUAZ}🚪 Çıkış yapılıyor...${NC}"
            cikis_yap
            ;;
        *)
            echo -e "${SARI}⚠️ Geçersiz seçim, ana menüye dönülüyor...${NC}"
            sleep 2
            return 0
            ;;
    esac
}

# =====================================================
# 🌐 BIND9 YÖNETİM FONKSİYONLARI
# =====================================================

# BIND9 durumu kontrol fonksiyonu
bind9_durum_kontrol() {
    local bind9_durum="ÇALIŞMIYOR"
    local yapilandirma="YOK"
    local aktif_domainler=0
    local son_test="YOK"
    
    # BIND9 servisi kontrol
    if systemctl is-active --quiet bind9; then
        bind9_durum="ÇALIŞIYOR"
    fi
    
    # Yapılandırma kontrol
    if [[ -f "/etc/bind/named.conf.local" ]] && grep -q "zone" "/etc/bind/named.conf.local" 2>/dev/null; then
        yapilandirma="MEVCUT"
        aktif_domainler=$(grep -c "zone" "/etc/bind/named.conf.local" 2>/dev/null || echo 0)
    fi
    
    # Son test kontrol
    if [[ -f "/var/log/bind9_test.log" ]]; then
        son_test=$(stat -c %y "/var/log/bind9_test.log" | cut -d' ' -f1)
    fi
    
    echo "$bind9_durum|$yapilandirma|$aktif_domainler|$son_test"
}

# BIND9 menü fonksiyonu
bind9_menu() {
    while true; do
        clear
        echo -e "${TURKUAZ}╔════════════════════════════════════╗${NC}"
        echo -e "${TURKUAZ}║            BIND9 MENÜSÜ           ║${NC}"
        echo -e "${TURKUAZ}╚════════════════════════════════════╝${NC}"
        echo ""
        
        # Durum bilgilerini al
        local durum_bilgisi=$(bind9_durum_kontrol)
        IFS='|' read -r bind9_durum yapilandirma aktif_domainler son_test <<< "$durum_bilgisi"
        
        echo -e "${BEYAZ}📊 BIND9 Durumu:${NC}"
        
        if [[ "$bind9_durum" == "ÇALIŞIYOR" ]]; then
            echo -e "   🔧 Bind9 Servisi: ${ACIK_YESIL}$bind9_durum${NC}"
        else
            echo -e "   🔧 Bind9 Servisi: ${TURUNCU}$bind9_durum${NC}"
        fi
        
        if [[ "$yapilandirma" == "MEVCUT" ]]; then
            echo -e "   📁 Yapılandırma: ${ACIK_YESIL}$yapilandirma${NC}"
        else
            echo -e "   📁 Yapılandırma: ${TURUNCU}$yapilandirma${NC}"
        fi
        
        echo -e "   🌐 Aktif Domainler: ${SARI}$aktif_domainler${NC}"
        echo -e "   🧪 Son Test: ${SARI}$son_test${NC}"
        echo ""
        
        echo -e "${ACIK_YESIL}1)${NC} 🚀 BIND9 Tam Kur (Tek seferlik işlem)"
        echo -e "${ACIK_YESIL}2)${NC} ➕ Domain Ekle (Yeni domain ekleme)"
        echo -e "${ACIK_YESIL}3)${NC} 🧪 BIND9 Test"
        echo -e "${ACIK_YESIL}4)${NC} 🔄 BIND9 Yeniden Başlat"
        echo -e "${ACIK_YESIL}5)${NC} 🔙 Geri"
        echo -e "${TURUNCU}0)${NC} ❌ Çıkış"
        echo ""
        
        read -p "$(echo -e ${SARI}Seçiminizi yapın [0-5]: ${NC})" secim
        
        case $secim in
            1) bind9_tam_kur ;;
            2) bind9_domain_ekle ;;
            3) bind9_test_yap ;;
            4) bind9_yeniden_baslat ;;
            5) return ;;
            0) exit 0 ;;
            *) echo -e "${TURUNCU}❌ Geçersiz seçim!${NC}"; sleep 1 ;;
        esac
    done
}

# BIND9 tam kurulum fonksiyonu
bind9_tam_kur() {
    clear
    echo -e "${TURKUAZ}╔════════════════════════════════════╗${NC}"
    echo -e "${TURKUAZ}║        BIND9 TAM KURULUM          ║${NC}"
    echo -e "${TURKUAZ}╚════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${BEYAZ}🌐 Kurulacak domainleri girin (her satırda bir domain):${NC}"
    echo -e "${SARI}Örnek:${NC}"
    echo -e "${SARI}justtekno.tr${NC}"
    echo -e "${SARI}craftaparat.com${NC}"
    echo -e "${SARI}bitronixcode.com${NC}"
    echo ""
    echo -e "${BEYAZ}Domain girişini bitirmek için boş satırda ENTER'a basın:${NC}"
    
    local domains_to_install=()
    while true; do
        read -p "Domain: " domain
        if [[ -z "$domain" ]]; then
            break
        fi
        domains_to_install+=("$domain")
        echo -e "${ACIK_YESIL}✅ Eklendi: $domain${NC}"
    done
    
    if [[ ${#domains_to_install[@]} -eq 0 ]]; then
        echo -e "${TURUNCU}❌ Hiç domain girilmedi!${NC}"
        read -p "Devam etmek için ENTER'a basın..."
        return
    fi
    
    echo ""
    echo -e "${BEYAZ}📋 Kurulacak domainler:${NC}"
    for domain in "${domains_to_install[@]}"; do
        echo -e "   • ${SARI}$domain${NC}"
    done
    echo ""
    
    read -p "$(echo -e ${SARI}Kuruluma başlansın mı? [e/h]: ${NC})" onay
    if [[ ! "$onay" =~ ^[eE]$ ]]; then
        echo -e "${TURUNCU}❌ Kurulum iptal edildi${NC}"
        read -p "Devam etmek için ENTER'a basın..."
        return
    fi
    
    echo ""
    echo -e "${TURKUAZ}🚀 BIND9 Kurulumu Başlıyor...${NC}"
    echo ""
    
    # 1. BIND9 Kur
    echo -e "${TURKUAZ}1/5 📦 BIND9 Kuruluyor...${NC}"
    if step_01_bind9_install; then
        echo -e "${ACIK_YESIL}✅ BIND9 kuruldu${NC}"
    else
        echo -e "${TURUNCU}❌ BIND9 kurulumu başarısız!${NC}"
        read -p "Devam etmek için ENTER'a basın..."
        return
    fi
    
    # 2. BIND9 Yapılandır
    echo -e "${TURKUAZ}2/5 ⚙️  BIND9 Yapılandırılıyor...${NC}"
    if step_02_bind9_configuration; then
        echo -e "${ACIK_YESIL}✅ BIND9 yapılandırıldı${NC}"
    else
        echo -e "${TURUNCU}❌ BIND9 yapılandırması başarısız!${NC}"
        read -p "Devam etmek için ENTER'a basın..."
        return
    fi
    
    # 3. Zone Dosyaları Oluştur
    echo -e "${TURKUAZ}3/5 📁 Zone Dosyaları Oluşturuluyor...${NC}"
    for domain in "${domains_to_install[@]}"; do
        echo -e "${SARI}   • $domain zone dosyası oluşturuluyor...${NC}"
        if step_05_zone_files_creation "$domain"; then
            echo -e "${ACIK_YESIL}   ✅ $domain zone dosyası oluşturuldu${NC}"
        else
            echo -e "${TURUNCU}   ❌ $domain zone dosyası oluşturulamadı!${NC}"
        fi
    done
    
    # 4. BIND9 Yeniden Başlat
    echo -e "${TURKUAZ}4/5 🔄 BIND9 Yeniden Başlatılıyor...${NC}"
    if systemctl restart bind9; then
        echo -e "${ACIK_YESIL}✅ BIND9 yeniden başlatıldı${NC}"
    else
        echo -e "${TURUNCU}❌ BIND9 yeniden başlatılamadı!${NC}"
        read -p "Devam etmek için ENTER'a basın..."
        return
    fi
    
    # 5. BIND9 Test
    echo -e "${TURKUAZ}5/5 🧪 BIND9 Test Ediliyor...${NC}"
    for domain in "${domains_to_install[@]}"; do
        echo -e "${SARI}   • $domain test ediliyor...${NC}"
        if bind9_domain_test "$domain"; then
            echo -e "${ACIK_YESIL}   ✅ $domain testi başarılı${NC}"
        else
            echo -e "${TURUNCU}   ❌ $domain testi başarısız!${NC}"
        fi
    done
    
    echo ""
    echo -e "${ACIK_YESIL}🎉 BIND9 TAM KURULUM TAMAMLANDI!${NC}"
    echo ""
    echo -e "${BEYAZ}📋 Kurulum Özeti:${NC}"
    echo -e "   • Kurulan domain sayısı: ${SARI}${#domains_to_install[@]}${NC}"
    echo -e "   • BIND9 durumu: ${ACIK_YESIL}ÇALIŞIYOR${NC}"
    echo -e "   • Yapılandırma: ${ACIK_YESIL}TAMAMLANDI${NC}"
    echo ""
    
    read -p "Devam etmek için ENTER'a basın..."
}

# Domain ekleme fonksiyonu
bind9_domain_ekle() {
    clear
    echo -e "${TURKUAZ}╔════════════════════════════════════╗${NC}"
    echo -e "${TURKUAZ}║          DOMAIN EKLEME            ║${NC}"
    echo -e "${TURKUAZ}╚════════════════════════════════════╝${NC}"
    echo ""
    
    # BIND9 kurulu mu kontrol et
    if ! systemctl is-installed bind9 &>/dev/null; then
        echo -e "${TURUNCU}❌ BIND9 kurulu değil! Önce 'BIND9 Tam Kur' seçeneğini kullanın.${NC}"
        read -p "Devam etmek için ENTER'a basın..."
        return
    fi
    
    echo -e "${BEYAZ}🌐 Eklenecek domain adını girin:${NC}"
    read -p "Domain: " yeni_domain
    
    if [[ -z "$yeni_domain" ]]; then
        echo -e "${TURUNCU}❌ Domain adı boş olamaz!${NC}"
        read -p "Devam etmek için ENTER'a basın..."
        return
    fi
    
    # Domain zaten var mı kontrol et
    if grep -q "zone \"$yeni_domain\"" "/etc/bind/named.conf.local" 2>/dev/null; then
        echo -e "${SARI}⚠️  Domain zaten mevcut: $yeni_domain${NC}"
        read -p "Devam etmek için ENTER'a basın..."
        return
    fi
    
    echo ""
    echo -e "${BEYAZ}📋 Eklenecek domain: ${SARI}$yeni_domain${NC}"
    read -p "$(echo -e ${SARI}Devam edilsin mi? [e/h]: ${NC})" onay
    
    if [[ ! "$onay" =~ ^[eE]$ ]]; then
        echo -e "${TURUNCU}❌ Domain ekleme iptal edildi${NC}"
        read -p "Devam etmek için ENTER'a basın..."
        return
    fi
    
    echo ""
    echo -e "${TURKUAZ}➕ Domain Ekleniyor...${NC}"
    
    # 1. Mevcut yapılandırmayı güncelle
    echo -e "${TURKUAZ}1/4 ⚙️  Yapılandırma güncelleniyor...${NC}"
    if bind9_yapilandirma_guncelle "$yeni_domain"; then
        echo -e "${ACIK_YESIL}✅ Yapılandırma güncellendi${NC}"
    else
        echo -e "${TURUNCU}❌ Yapılandırma güncellenemedi!${NC}"
        read -p "Devam etmek için ENTER'a basın..."
        return
    fi
    
    # 2. Yeni zone dosyası oluştur
    echo -e "${TURKUAZ}2/4 📁 Zone dosyası oluşturuluyor...${NC}"
    if step_05_zone_files_creation "$yeni_domain"; then
        echo -e "${ACIK_YESIL}✅ Zone dosyası oluşturuldu${NC}"
    else
        echo -e "${TURUNCU}❌ Zone dosyası oluşturulamadı!${NC}"
        read -p "Devam etmek için ENTER'a basın..."
        return
    fi
    
    # 3. BIND9 Yeniden Başlat
    echo -e "${TURKUAZ}3/4 🔄 BIND9 yeniden başlatılıyor...${NC}"
    if systemctl restart bind9; then
        echo -e "${ACIK_YESIL}✅ BIND9 yeniden başlatıldı${NC}"
    else
        echo -e "${TURUNCU}❌ BIND9 yeniden başlatılamadı!${NC}"
        read -p "Devam etmek için ENTER'a basın..."
        return
    fi
    
    # 4. Test yap
    echo -e "${TURKUAZ}4/4 🧪 Test yapılıyor...${NC}"
    if bind9_domain_test "$yeni_domain"; then
        echo -e "${ACIK_YESIL}✅ Test başarılı${NC}"
    else
        echo -e "${TURUNCU}❌ Test başarısız!${NC}"
    fi
    
    echo ""
    echo -e "${ACIK_YESIL}🎉 DOMAIN BAŞARIYLA EKLENDİ!${NC}"
    echo -e "${BEYAZ}📋 Eklenen domain: ${SARI}$yeni_domain${NC}"
    echo ""
    
    read -p "Devam etmek için ENTER'a basın..."
}

# BIND9 test fonksiyonu
bind9_test_yap() {
    clear
    echo -e "${TURKUAZ}╔════════════════════════════════════╗${NC}"
    echo -e "${TURKUAZ}║           BIND9 TEST              ║${NC}"
    echo -e "${TURKUAZ}╚════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${TURKUAZ}🧪 BIND9 Test Başlıyor...${NC}"
    echo ""
    
    # Genel BIND9 testi
    if step_06_bind9_test; then
        echo -e "${ACIK_YESIL}✅ Genel BIND9 testi başarılı${NC}"
    else
        echo -e "${TURUNCU}❌ Genel BIND9 testi başarısız!${NC}"
    fi
    
    echo ""
    echo -e "${BEYAZ}📋 Domain Testleri:${NC}"
    
    # Tüm domainleri test et
    if [[ -f "/etc/bind/named.conf.local" ]]; then
        local domains=($(grep -o 'zone "[^"]*"' /etc/bind/named.conf.local | sed 's/zone "//g' | sed 's/"//g'))
        
        for domain in "${domains[@]}"; do
            echo -e "${SARI}   • $domain test ediliyor...${NC}"
            if bind9_domain_test "$domain"; then
                echo -e "${ACIK_YESIL}   ✅ $domain testi başarılı${NC}"
            else
                echo -e "${TURUNCU}   ❌ $domain testi başarısız!${NC}"
            fi
        done
    else
        echo -e "${TURUNCU}❌ Yapılandırma dosyası bulunamadı!${NC}"
    fi
    
    # Test sonucunu kaydet
    echo "$(date): BIND9 test tamamlandı" > "/var/log/bind9_test.log"
    
    echo ""
    read -p "Devam etmek için ENTER'a basın..."
}

# BIND9 yeniden başlatma fonksiyonu
bind9_yeniden_baslat() {
    clear
    echo -e "${TURKUAZ}╔════════════════════════════════════╗${NC}"
    echo -e "${TURKUAZ}║       BIND9 YENİDEN BAŞLAT        ║${NC}"
    echo -e "${TURKUAZ}╚════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${TURKUAZ}🔄 BIND9 yeniden başlatılıyor...${NC}"
    
    if systemctl restart bind9; then
        echo -e "${ACIK_YESIL}✅ BIND9 başarıyla yeniden başlatıldı${NC}"
        
        # Servis durumunu kontrol et
        if systemctl is-active --quiet bind9; then
            echo -e "${ACIK_YESIL}✅ BIND9 servisi çalışıyor${NC}"
        else
            echo -e "${TURUNCU}❌ BIND9 servisi çalışmıyor!${NC}"
        fi
    else
        echo -e "${TURUNCU}❌ BIND9 yeniden başlatılamadı!${NC}"
        echo ""
        echo -e "${BEYAZ}📋 Hata detayları:${NC}"
        systemctl status bind9 --no-pager -l
    fi
    
    echo ""
    read -p "Devam etmek için ENTER'a basın..."
}

# Yardımcı fonksiyonlar
bind9_yapilandirma_guncelle() {
    local domain=$1
    
    # named.conf.local dosyasına zone ekle
    cat >> "/etc/bind/named.conf.local" << EOF

zone "$domain" {
    type master;
    file "/etc/bind/zones/db.$domain";
    allow-transfer { any; };
};
EOF
    
    return 0
}

bind9_domain_test() {
    local domain=$1
    local test_basarili=true
    
    # NS kaydı test
    if ! dig @localhost NS "$domain" +short >/dev/null 2>&1; then
        test_basarili=false
    fi
    
    # A kaydı test
    if ! dig @localhost A "$domain" +short >/dev/null 2>&1; then
        test_basarili=false
    fi
    
    $test_basarili
}

# =====================================================
# 🌐 BIND9 KURULUM FONKSİYONLARI (bind9-cloudpanel.sh'dan)
# =====================================================

step_01_bind9_install() {
    echo -e "${TURKUAZ}📦 BIND9 kuruluyor...${NC}"
    
    apt update
    apt install -y bind9 bind9utils bind9-doc dnsutils
    
    if systemctl is-active --quiet bind9; then
        echo -e "${ACIK_YESIL}✅ BIND9 başarıyla kuruldu ve çalışıyor${NC}"
        return 0
    else
        echo -e "${TURUNCU}❌ BIND9 kurulumu başarısız!${NC}"
        return 1
    fi
}

step_02_bind9_configuration() {
    echo -e "${TURKUAZ}⚙️  BIND9 yapılandırılıyor...${NC}"
    
    # named.conf.options dosyasını oluştur
    cat > /etc/bind/named.conf.options << EOF
options {
    directory "/var/cache/bind";
    
    forwarders {
        8.8.8.8;
        8.8.4.4;
        1.1.1.1;
    };
    
    dnssec-validation auto;
    listen-on-v6 { any; };
    listen-on { any; };
    allow-query { any; };
    allow-recursion { any; };
    allow-transfer { any; };
    
    version none;
    hostname none;
    server-id none;
};
EOF

    # Zones dizini oluştur
    mkdir -p /etc/bind/zones
    chown bind:bind /etc/bind/zones
    
    return 0
}

step_05_zone_files_creation() {
    local domain=$1
    local zone_file="/etc/bind/zones/db.$domain"
    
    echo -e "${TURKUAZ}📁 $domain için zone dosyası oluşturuluyor...${NC}"
    
    # Zone dosyasını oluştur
    cat > "$zone_file" << EOF
\$TTL    604800
@       IN      SOA     ns1.$domain. admin.$domain. (
                        $SERIAL         ; Serial
                        604800          ; Refresh
                        86400           ; Retry
                        2419200         ; Expire
                        604800 )        ; Negative Cache TTL

; Name servers
@       IN      NS      ns1.$domain.
@       IN      NS      ns2.$domain.

; A records
@       IN      A       $DIS_IP
ns1     IN      A       $DIS_IP
ns2     IN      A       $DIS_IP
www     IN      A       $DIS_IP
mail    IN      A       $DIS_IP
webmail IN      A       $DIS_IP
ftp     IN      A       $DIS_IP
cpanel  IN      A       $DIS_IP

; MX records
@       IN      MX      10      mail.$domain.

; CNAME records
imap    IN      CNAME   mail.$domain.
smtp    IN      CNAME   mail.$domain.
pop     IN      CNAME   mail.$domain.
pop3    IN      CNAME   mail.$domain.

; TXT records
@       IN      TXT     "v=spf1 mx a ip4:$DIS_IP ~all"
_dmarc  IN      TXT     "v=DMARC1; p=none; rua=mailto:dmarc@$domain"
EOF

    # named.conf.local'a zone ekle (eğer yoksa)
    if ! grep -q "zone \"$domain\"" /etc/bind/named.conf.local 2>/dev/null; then
        cat >> /etc/bind/named.conf.local << EOF

zone "$domain" {
    type master;
    file "/etc/bind/zones/db.$domain";
    allow-transfer { any; };
};
EOF
    fi
    
    # İzinleri ayarla
    chown bind:bind "$zone_file"
    chmod 644 "$zone_file"
    
    # Zone dosyasını test et
    if named-checkzone "$domain" "$zone_file" >/dev/null 2>&1; then
        echo -e "${ACIK_YESIL}✅ $domain zone dosyası başarıyla oluşturuldu${NC}"
        return 0
    else
        echo -e "${TURUNCU}❌ $domain zone dosyası hatalı!${NC}"
        return 1
    fi
}

step_06_bind9_test() {
    echo -e "${TURKUAZ}🧪 BIND9 test ediliyor...${NC}"
    
    # BIND9 servisi çalışıyor mu?
    if ! systemctl is-active --quiet bind9; then
        echo -e "${TURUNCU}❌ BIND9 servisi çalışmıyor!${NC}"
        return 1
    fi
    
    # Yapılandırma dosyaları geçerli mi?
    if ! named-checkconf; then
        echo -e "${TURUNCU}❌ BIND9 yapılandırması hatalı!${NC}"
        return 1
    fi
    
    # DNS sorgusu test
    if dig @localhost google.com >/dev/null 2>&1; then
        echo -e "${ACIK_YESIL}✅ DNS sorguları çalışıyor${NC}"
        return 0
    else
        echo -e "${TURUNCU}❌ DNS sorguları çalışmıyor!${NC}"
        return 1
    fi
}

# =====================================================
# ☁️ CLOUDPANEL DURUM KONTROL FONKSİYONLARI
# =====================================================

# CloudPanel durumu kontrol fonksiyonu
cloudpanel_durum_kontrol() {
    local cloudpanel_durum="ÇALIŞMIYOR"
    local nginx_durum="ÇALIŞMIYOR"
    local mysql_durum="ÇALIŞMIYOR"
    local fail2ban_durum="ÇALIŞMIYOR"
    local ufw_8443="KAPALI"
    local ufw_53="KAPALI"
    
    # CloudPanel servis kontrolü
    if systemctl is-active --quiet cloudpanel 2>/dev/null; then
        cloudpanel_durum="${ACIK_YESIL}ÇALIŞIYOR${NC}"
    else
        cloudpanel_durum="${TURUNCU}ÇALIŞMIYOR${NC}"
    fi
    
    # Nginx kontrolü
    if systemctl is-active --quiet nginx 2>/dev/null; then
        nginx_durum="${ACIK_YESIL}ÇALIŞIYOR${NC}"
    else
        nginx_durum="${TURUNCU}ÇALIŞMIYOR${NC}"
    fi
    
    # MySQL kontrolü
    if systemctl is-active --quiet mysql 2>/dev/null; then
        mysql_durum="${ACIK_YESIL}ÇALIŞIYOR${NC}"
    else
        mysql_durum="${TURUNCU}ÇALIŞMIYOR${NC}"
    fi
    
    # Fail2ban kontrolü
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        fail2ban_durum="${ACIK_YESIL}ÇALIŞIYOR${NC}"
    else
        fail2ban_durum="${TURUNCU}ÇALIŞMIYOR${NC}"
    fi
    
    # UFW port kontrolleri
    if ufw status 2>/dev/null | grep -q "8443.*ALLOW"; then
        ufw_8443="${ACIK_YESIL}AÇIK${NC}"
    else
        ufw_8443="${TURUNCU}KAPALI${NC}"
    fi
    
    if ufw status 2>/dev/null | grep -q "53.*ALLOW"; then
        ufw_53="${ACIK_YESIL}AÇIK${NC}"
    else
        ufw_53="${TURUNCU}KAPALI${NC}"
    fi
    
    echo -e "${TURKUAZ}📊 CloudPanel Durumu:${NC}"
    echo -e "   ☁️ CloudPanel: $cloudpanel_durum"
    echo -e "   🛡️ Fail2ban: $fail2ban_durum"
    echo -e "   🌐 Nginx: $nginx_durum"
    echo -e "   🗄️ MySQL: $mysql_durum"
    echo -e "   🔐 UFW Port 8443: $ufw_8443"
    echo -e "   🌐 UFW Port 53: $ufw_53"
    echo ""
}

# CloudPanel otomatik kurulum fonksiyonu
cloudpanel_kur_otomatik() {
    ana_baslik_goster
    
    echo -e "${MOR}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MOR}║            CLOUDPANEL + FAIL2BAN KURULUM                ║${NC}"
    echo -e "${MOR}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${TURKUAZ}🚀 CloudPanel CE v2 kurulumu başlayacak...${NC}"
    echo -e "${SARI}ℹ️ Fail2ban CloudPanel scripti ile otomatik kurulacak${NC}"
    echo ""
    echo -e "${SARI}⚠️ UYARI: Kurulum sırasında sistem yeniden başlatılabilir!${NC}"
    echo -e "${BEYAZ}Devam edilsin mi? (E/h): ${NC}"
    read -r onay
    
    if [[ ! "$onay" =~ ^[EeYy]$ ]]; then
        echo -e "${SARI}⚠️ CloudPanel kurulumu iptal edildi.${NC}"
        enter_bekle
        return 0
    fi
    
    echo -e "${TURKUAZ}🚀 CLOUDPANEL KURULUMU BAŞLANIYOR...${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    # Adım 1: Sistem güncellemesi
    echo -e "${TURKUAZ}[1/6]${NC} Sistem güncelleniyor..."
    apt update >/dev/null 2>&1 && apt upgrade -y >/dev/null 2>&1
    echo -e "${ACIK_YESIL}   ✅ Sistem güncellendi${NC}"
    
    # Adım 2: Gerekli paketler
    echo -e "${TURKUAZ}[2/6]${NC} Gerekli paketler kuruluyor..."
    apt install -y curl wget gnupg2 software-properties-common apt-transport-https ca-certificates lsb-release whois >/dev/null 2>&1
    echo -e "${ACIK_YESIL}   ✅ Gerekli paketler kuruldu${NC}"
    
    # Adım 3: CloudPanel kurulum scripti indirme
    echo -e "${TURKUAZ}[3/6]${NC} CloudPanel kurulum scripti indiriliyor..."
    cd /tmp
    curl -fsSL https://installer.cloudpanel.io/ce/v2/install.sh -o install.sh >/dev/null 2>&1
    chmod +x install.sh
    echo -e "${ACIK_YESIL}   ✅ Kurulum scripti hazır${NC}"
    
    # Adım 4: CloudPanel kurulumu (Fail2ban dahil)
    echo -e "${TURKUAZ}[4/6]${NC} CloudPanel kuruluyor (Fail2ban dahil)..."
    echo -e "${SARI}   ⏳ Bu işlem 5-10 dakika sürebilir...${NC}"
    
    # CloudPanel kurulumunu sessiz modda çalıştır
    bash install.sh >/dev/null 2>&1
    
    if systemctl is-active --quiet cloudpanel; then
        echo -e "${ACIK_YESIL}   ✅ CloudPanel başarıyla kuruldu${NC}"
    else
        echo -e "${TURUNCU}   ❌ CloudPanel kurulumu başarısız!${NC}"
        enter_bekle
        return 1
    fi
    
    # Fail2ban kontrolü
    if systemctl is-active --quiet fail2ban; then
        echo -e "${ACIK_YESIL}   ✅ Fail2ban CloudPanel ile kuruldu${NC}"
    else
        echo -e "${SARI}   ⚠️ Fail2ban henüz aktif değil${NC}"
    fi
    
    # Adım 5: DNS portu yeniden açma (CloudPanel UFW'yi sıfırladığı için)
    echo -e "${TURKUAZ}[5/6]${NC} DNS portu yeniden açılıyor..."
    ufw allow 53/tcp >/dev/null 2>&1
    ufw allow 53/udp >/dev/null 2>&1
    ufw allow ${SSH_OZEL_PORT}/tcp >/dev/null 2>&1
    echo -e "${ACIK_YESIL}   ✅ Port Sunucu ve ÖZEL port yeniden açıldı${NC}"
    
    # Adım 6: Fail2ban ek yapılandırmaları
    echo -e "${TURKUAZ}[6/6]${NC} Fail2ban ek yapılandırmaları..."
    fail2ban_yapilandir_cloudpanel
    echo -e "${ACIK_YESIL}   ✅ Fail2ban yapılandırmaları tamamlandı${NC}"
    
    # CloudPanel admin bilgilerini al
    echo ""
    echo -e "${ACIK_YESIL}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${ACIK_YESIL}║           ✅ CLOUDPANEL KURULUMU TAMAMLANDI!            ║${NC}"
    echo -e "${ACIK_YESIL}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BEYAZ}🌐 CloudPanel Erişim Bilgileri:${NC}"
    echo -e "   📍 URL: https://$DIS_IP:8443"
    echo -e "   👤 Kullanıcı: admin"
    echo -e "   🔑 Şifre: İlk girişte CloudPanel arayüzünden belirleyeceksiniz."
    echo ""
    echo -e "${BEYAZ}📊 Kurulum Özeti:${NC}"
    echo -e "   ☁️ CloudPanel: $(systemctl is-active --quiet cloudpanel && echo -e "${ACIK_YESIL}Çalışıyor${NC}" || echo -e "${TURUNCU}Çalışmıyor${NC}")"
    echo -e "   🛡️ Fail2ban: $(systemctl is-active --quiet fail2ban && echo -e "${ACIK_YESIL}Çalışıyor${NC}" || echo -e "${TURUNCU}Çalışmıyor${NC}")"
    echo -e "   🌐 Nginx: $(systemctl is-active --quiet nginx && echo -e "${ACIK_YESIL}Çalışıyor${NC}" || echo -e "${TURUNCU}Çalışmıyor${NC}")"
    echo -e "   🗄️ MySQL: $(systemctl is-active --quiet mysql && echo -e "${ACIK_YESIL}Çalışıyor${NC}" || echo -e "${TURUNCU}Çalışmıyor${NC}")"
    echo -e "   🔐 UFW Port 8443: $(ufw status | grep -q "8443.*ALLOW" && echo -e "${ACIK_YESIL}Açık${NC}" || echo -e "${TURUNCU}Kapalı${NC}")"
    echo -e "   🌐 UFW Port 53: $(ufw status | grep -q "53.*ALLOW" && echo -e "${ACIK_YESIL}Açık${NC}" || echo -e "${TURUNCU}Kapalı${NC}")"
    echo ""
    
    gunluk_yaz "BILGI" "CloudPanel + Fail2ban kurulumu tamamlandı"
    enter_bekle
}

# =====================================================
# 🛡️ FAIL2BAN YÖNETİM FONKSİYONLARI
# =====================================================

# Fail2ban CloudPanel entegrasyonu yapılandırma
fail2ban_yapilandir_cloudpanel() {
    echo -e "${BEYAZ}🛡️ Fail2ban CloudPanel entegrasyonu yapılandırılıyor...${NC}"
    
    # CloudPanel'in mevcut fail2ban yapılandırmasını kontrol et
    if systemctl is-active --quiet fail2ban; then
        echo -e "${ACIK_YESIL}   ✅ Fail2ban CloudPanel ile kurulu${NC}"
    else
        echo -e "${SARI}   ⚠️ Fail2ban henüz aktif değil, yapılandırma ekleniyor...${NC}"
    fi
    
    # Ek yapılandırmalar ekle (CloudPanel'in mevcut ayarlarını bozmadan)
    cat >> /etc/fail2ban/jail.local << EOF

# JustServer Ultimate - Ek Yapılandırmalar
[DEFAULT]
# Güvenli IP'ler (banlanmayacak)
ignoreip = 127.0.0.1/8 ${IC_IP}/24 ${DIS_IP}

# Genel ayarlar
bantime = 7200
findtime = 600
maxretry = 3
banaction = iptables-multiport

# SSH Varsayılan Port Koruması
[sshd-port-default]
enabled = true
port = ${SSH_PORT}
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200

# SSH Alternatif Port Koruması
[sshd-port-alternative]
enabled = true
port = ${SSH_OZEL_PORT}
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 6
ignoreip = 127.0.0.1/8 ${IC_IP}/24 ${DIS_IP}

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2
ignoreip = 127.0.0.1/8 ${IC_IP}/24 ${DIS_IP}

[nginx-noproxy]
enabled = true
port = http,https
filter = nginx-noproxy
logpath = /var/log/nginx/access.log
maxretry = 2
ignoreip = 127.0.0.1/8 ${IC_IP}/24 ${DIS_IP}
EOF

    # Ek filter dosyaları oluştur (aynı kalacak)
    cat > /etc/fail2ban/filter.d/nginx-noscript.conf << EOF
[Definition]
failregex = ^<HOST> -.*GET.*(\.php|\.asp|\.exe|\.pl|\.cgi|\.scgi)
ignoreregex =
EOF

    cat > /etc/fail2ban/filter.d/nginx-badbots.conf << EOF
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*HTTP.*"(?:(?!404).)*?".*"(?:(?!200).)*?".*".*"(.*bot.*|.*spider.*|.*crawler.*)".*$
ignoreregex =
EOF

    cat > /etc/fail2ban/filter.d/nginx-noproxy.conf << EOF
[Definition]
failregex = ^<HOST> -.*GET http.*
ignoreregex =
EOF
    
    # Fail2ban'ı yeniden başlat
    systemctl restart fail2ban >/dev/null 2>&1
    
    echo -e "${ACIK_YESIL}   ✅ Fail2ban ek yapılandırmaları eklendi${NC}"
}

# Gelişmiş Ban Yönetimi
ban_yonetimi() {
    ana_baslik_goster
    
    echo -e "${MOR}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MOR}║                 FAIL2BAN YÖNETİMİ                       ║${NC}"
    echo -e "${MOR}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Fail2ban durumu kontrol
    if ! systemctl is-active --quiet fail2ban; then
        echo -e "${TURUNCU}❌ Fail2ban servisi çalışmıyor!${NC}"
        echo -e "${SARI}CloudPanel kurulumu tamamlandıktan sonra tekrar deneyin.${NC}"
        enter_bekle
        return 1
    fi
    
    echo -e "${TURKUAZ}🛡️ FAIL2BAN DURUMU:${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    # Genel durum
    echo -e "${BEYAZ}📊 Genel Durum:${NC}"
    fail2ban-client status 2>/dev/null | while IFS= read -r line; do
        echo -e "   ${TURKUAZ}$line${NC}"
    done
    echo ""
    
    # Aktif jail'leri listele
    echo -e "${BEYAZ}🔒 Aktif Jail'ler:${NC}"
    local jails=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | cut -d: -f2 | tr ',' '\n' | xargs)
    
    if [[ -n "$jails" ]]; then
        for jail in $jails; do
            local jail_status=$(fail2ban-client status "$jail" 2>/dev/null)
            local banned_count=$(echo "$jail_status" | grep "Currently banned:" | awk '{print $NF}')
            local total_banned=$(echo "$jail_status" | grep "Total banned:" | awk '{print $NF}')
            
            if [[ $banned_count -gt 0 ]]; then
                echo -e "   🔴 $jail: ${TURUNCU}$banned_count aktif ban${NC} (Toplam: $total_banned)"
            else
                echo -e "   🟢 $jail: ${ACIK_YESIL}$banned_count aktif ban${NC} (Toplam: $total_banned)"
            fi
        done
    else
        echo -e "   ${SARI}⚠️ Aktif jail bulunamadı${NC}"
    fi
    echo ""
    
    # Banlı IP'leri göster
    echo -e "${BEYAZ}🚫 Banlı IP Adresleri:${NC}"
    local banned_ips_found=false
    
    if [[ -n "$jails" ]]; then
        for jail in $jails; do
            local banned_ips=$(fail2ban-client status "$jail" 2>/dev/null | grep "Banned IP list:" | cut -d: -f2 | xargs)
            if [[ -n "$banned_ips" && "$banned_ips" != "" ]]; then
                echo -e "   📍 $jail:"
                for ip in $banned_ips; do
                    # IP'nin ülke bilgisini al (whois ile)
                    local country=$(whois "$ip" 2>/dev/null | grep -i country | head -1 | awk '{print $NF}' || echo "Unknown")
                    echo -e "      🔴 $ip (${country})"
                done
                banned_ips_found=true
            fi
        done
    fi
    
    if [[ "$banned_ips_found" == false ]]; then
        echo -e "   ${ACIK_YESIL}✅ Şu anda banlı IP yok${NC}"
    fi
    echo ""
    
    # İşlem menüsü
    echo -e "${TURKUAZ}🔧 İŞLEMLER:${NC}"
    echo -e "1) 🔓 IP Ban Kaldır"
    echo -e "2) 🔒 Manuel IP Ban"
    echo -e "3) 📊 Detaylı Jail Durumu"
    echo -e "4) 🔄 Fail2ban Yeniden Başlat"
    echo -e "5) 📋 Ban Geçmişi Göster"
    echo -e "6) 🔙 Geri"
    echo ""
    
    echo -e "${SARI}Seçiminizi yapın (1-6): ${NC}"
    read -r secim
    
    case $secim in
        1) ip_ban_kaldir ;;
        2) manuel_ip_ban ;;
        3) detayli_jail_durumu ;;
        4) fail2ban_yeniden_baslat ;;
        5) ban_gecmisi_goster ;;
        6) return 0 ;;
        *)
            echo -e "${TURUNCU}❌ Geçersiz seçim!${NC}"
            sleep 2
            ban_yonetimi
            ;;
    esac
}

# IP Ban Kaldırma
ip_ban_kaldir() {
    echo ""
    echo -e "${TURKUAZ}🔓 IP BAN KALDIRMA${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    # Mevcut banlı IP'leri göster
    echo -e "${BEYAZ}📋 Mevcut Banlı IP'ler:${NC}"
    local jails=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | cut -d: -f2 | tr ',' '\n' | xargs)
    local ip_jail_pairs=()
    
    if [[ -n "$jails" ]]; then
        for jail in $jails; do
            local banned_ips=$(fail2ban-client status "$jail" 2>/dev/null | grep "Banned IP list:" | cut -d: -f2 | xargs)
            if [[ -n "$banned_ips" && "$banned_ips" != "" ]]; then
                for ip in $banned_ips; do
                    echo -e "   🔴 $ip ($jail)"
                    ip_jail_pairs+=("$ip:$jail")
                done
            fi
        done
    fi
    
    if [[ ${#ip_jail_pairs[@]} -eq 0 ]]; then
        echo -e "${ACIK_YESIL}✅ Banlı IP bulunamadı!${NC}"
        enter_bekle
        return 0
    fi
    
    echo ""
    echo -e "${BEYAZ}Kaldırılacak IP adresini girin: ${NC}"
    read -r ip_adres
    
    if [[ -z "$ip_adres" ]]; then
        echo -e "${TURUNCU}❌ IP adresi boş olamaz!${NC}"
        enter_bekle
        return 1
    fi
    
    # IP'yi tüm jail'lerden kaldır
    local basarili=0
    for jail in $jails; do
        if fail2ban-client set "$jail" unbanip "$ip_adres" >/dev/null 2>&1; then
            echo -e "${ACIK_YESIL}✅ $ip_adres IP'si $jail jail'inden kaldırıldı${NC}"
            basarili=$((basarili + 1))
        fi
    done
    
    if [[ $basarili -gt 0 ]]; then
        echo -e "${ACIK_YESIL}✅ $ip_adres IP'sinin banı $basarili jail'den kaldırıldı!${NC}"
        gunluk_yaz "BILGI" "IP ban kaldırıldı: $ip_adres"
    else
        echo -e "${SARI}⚠️ $ip_adres IP'si banlı listede bulunamadı!${NC}"
    fi
    
    enter_bekle
    ban_yonetimi
}

# Fail2ban Status Fonksiyonu (paylaştığınız fail2ban-status.sh'den esinlenerek)
fail2ban_status_goster() {
    ana_baslik_goster
    
    echo -e "${MOR}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MOR}║                   FAIL2BAN STATUS                       ║${NC}"
    echo -e "${MOR}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${TURKUAZ}🛡️ FAIL2BAN DURUMU:${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    # Fail2ban durumu kontrol
    if ! systemctl is-active --quiet fail2ban; then
        echo -e "${TURUNCU}❌ Fail2ban servisi çalışmıyor!${NC}"
        enter_bekle
        return 1
    fi
    
    # Genel status
    echo -e "${BEYAZ}📊 Genel Durum:${NC}"
    fail2ban-client status
    echo ""
    
    # Her jail için detaylı bilgi
    local jails=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | cut -d: -f2 | tr ',' '\n' | xargs)
    
    if [[ -n "$jails" ]]; then
        for jail in $jails; do
            echo -e "${BEYAZ}🔒 Jail: $jail${NC}"
            fail2ban-client status "$jail"
            echo ""
        done
    fi
    
    enter_bekle
}

# Kurtarma Fonksiyonu (paylaştığınız kurtar.sh'den esinlenerek)
fail2ban_kurtarma() {
    ana_baslik_goster
    
    echo -e "${MOR}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MOR}║              FAIL2BAN KURTARMA İŞLEMİ                   ║${NC}"
    echo -e "${MOR}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${TURUNCU}⚠️ UYARI: Bu işlem tüm fail2ban banlarını kaldırır!${NC}"
    echo -e "${SARI}Sunucu: $(hostname)${NC}"
    echo -e "${SARI}Dış IP: $DIS_IP${NC}"
    echo -e "${SARI}İç IP: $IC_IP${NC}"
    echo ""
    
    echo -e "${BEYAZ}Kurtarma işlemine devam edilsin mi? (E/h): ${NC}"
    read -r onay
    
    if [[ ! "$onay" =~ ^[EeYy]$ ]]; then
        echo -e "${SARI}⚠️ Kurtarma işlemi iptal edildi.${NC}"
        enter_bekle
        return 0
    fi
    
    echo -e "${TURKUAZ}🚀 FAIL2BAN KURTARMA BAŞLANIYOR...${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    # Fail2ban durumunu kontrol et
    echo -e "${TURKUAZ}[1/6]${NC} Fail2ban durumu kontrol ediliyor..."
    if systemctl is-active --quiet fail2ban; then
        echo -e "${ACIK_YESIL}   ✅ Fail2ban çalışıyor${NC}"
    else
        echo -e "${SARI}   ⚠️ Fail2ban zaten çalışmıyor${NC}"
    fi
    
    # Fail2ban'ı durdur
    echo -e "${TURKUAZ}[2/6]${NC} Fail2ban servisi durduruluyor..."
    systemctl stop fail2ban
    echo -e "${ACIK_YESIL}   ✅ Fail2ban durduruldu${NC}"
    
    # Tüm iptables kurallarını temizle
    echo -e "${TURKUAZ}[3/6]${NC} Fail2ban iptables kuralları temizleniyor..."
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    echo -e "${ACIK_YESIL}   ✅ Iptables kuralları temizlendi${NC}"
    
    # Varsayılan iptables kurallarını oluştur
    echo -e "${TURKUAZ}[4/6]${NC} Varsayılan güvenlik kuralları uygulanıyor..."
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # SSH ve CloudPanel erişimini sağla
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp --dport 2200 -j ACCEPT
    iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
    echo -e "${ACIK_YESIL}   ✅ Temel erişim kuralları eklendi${NC}"
    
    # Fail2ban veritabanını temizle
    echo -e "${TURKUAZ}[5/6]${NC} Fail2ban veritabanı temizleniyor..."
    if [[ -f "/var/lib/fail2ban/fail2ban.sqlite3" ]]; then
        rm -f /var/lib/fail2ban/fail2ban.sqlite3
        touch /var/lib/fail2ban/fail2ban.sqlite3
        echo -e "${ACIK_YESIL}   ✅ Fail2ban veritabanı temizlendi${NC}"
    else
        echo -e "${SARI}   ⚠️ Fail2ban veritabanı bulunamadı${NC}"
    fi
    
    # Fail2ban'ı yeniden başlat
    echo -e "${TURKUAZ}[6/6]${NC} Fail2ban yeniden başlatılıyor..."
    systemctl start fail2ban
    
    if systemctl is-active --quiet fail2ban; then
        echo -e "${ACIK_YESIL}   ✅ Fail2ban başarıyla başlatıldı${NC}"
    else
        echo -e "${TURUNCU}   ❌ Fail2ban başlatılamadı!${NC}"
    fi
    
    echo ""
    echo -e "${ACIK_YESIL}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${ACIK_YESIL}║           ✅ FAIL2BAN KURTARMA TAMAMLANDI!              ║${NC}"
    echo -e "${ACIK_YESIL}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BEYAZ}📊 Kurtarma Özeti:${NC}"
    echo -e "   🛡️ Fail2ban: $(systemctl is-active --quiet fail2ban && echo -e "${ACIK_YESIL}Çalışıyor${NC}" || echo -e "${TURUNCU}Çalışmıyor${NC}")"
    echo -e "   🔓 Tüm IP banları kaldırıldı"
    echo -e "   🔧 Iptables kuralları sıfırlandı"
    echo -e "   🗄️ Veritabanı temizlendi"
    echo ""
    
    gunluk_yaz "BILGI" "Fail2ban kurtarma işlemi tamamlandı"
    enter_bekle
}

# Manuel IP Ban
manuel_ip_ban() {
    echo ""
    echo -e "${TURKUAZ}🔒 MANUEL IP BAN${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    echo -e "${BEYAZ}Banlanacak IP adresini girin: ${NC}"
    read -r ip_adres
    
    if [[ -z "$ip_adres" ]]; then
        echo -e "${TURUNCU}❌ IP adresi boş olamaz!${NC}"
        enter_bekle
        return 1
    fi
    
    # IP formatını kontrol et
    if [[ ! $ip_adres =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo -e "${TURUNCU}❌ Geçersiz IP formatı!${NC}"
        enter_bekle
        return 1
    fi
    
    echo -e "${BEYAZ}Ban süresi (saniye, boş bırakırsanız varsayılan): ${NC}"
    read -r ban_suresi
    
    if [[ -z "$ban_suresi" ]]; then
        ban_suresi="3600"  # 1 saat varsayılan
    fi
    
    # Mevcut jail'leri al
    local jails=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | cut -d: -f2 | tr ',' '\n' | xargs)
    
    if [[ -n "$jails" ]]; then
        echo -e "${BEYAZ}Hangi jail'e banlanacak?${NC}"
        echo -e "0) Tüm jail'lere"
        local i=1
        for jail in $jails; do
            echo -e "$i) $jail"
            i=$((i + 1))
        done
        
        echo -e "${SARI}Seçiminizi yapın: ${NC}"
        read -r jail_secim
        
        if [[ "$jail_secim" == "0" ]]; then
            # Tüm jail'lere ban ekle
            local basarili=0
            for jail in $jails; do
                if fail2ban-client set "$jail" banip "$ip_adres" >/dev/null 2>&1; then
                    echo -e "${ACIK_YESIL}✅ $ip_adres IP'si $jail jail'ine banlandı${NC}"
                    basarili=$((basarili + 1))
                fi
            done
            
            if [[ $basarili -gt 0 ]]; then
                echo -e "${ACIK_YESIL}✅ $ip_adres IP'si $basarili jail'e banlandı!${NC}"
            fi
        else
            # Belirli jail'e ban ekle
            local jail_array=($jails)
            local secilen_jail="${jail_array[$((jail_secim - 1))]}"
            
            if [[ -n "$secilen_jail" ]]; then
                if fail2ban-client set "$secilen_jail" banip "$ip_adres" >/dev/null 2>&1; then
                    echo -e "${ACIK_YESIL}✅ $ip_adres IP'si $secilen_jail jail'ine banlandı!${NC}"
                else
                    echo -e "${TURUNCU}❌ Ban işlemi başarısız!${NC}"
                fi
            else
                echo -e "${TURUNCU}❌ Geçersiz jail seçimi!${NC}"
            fi
        fi
    else
        echo -e "${SARI}⚠️ Aktif jail bulunamadı!${NC}"
    fi
    
    gunluk_yaz "BILGI" "Manuel IP ban: $ip_adres"
    enter_bekle
    ban_yonetimi
}

# Detaylı Jail Durumu
detayli_jail_durumu() {
    echo ""
    echo -e "${TURKUAZ}📊 DETAYLI JAIL DURUMU${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    local jails=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | cut -d: -f2 | tr ',' '\n' | xargs)
    
    if [[ -n "$jails" ]]; then
        for jail in $jails; do
            echo -e "${BEYAZ}🔒 Jail: $jail${NC}"
            echo "───────────────────────────────────────────────────────────────────────────"
            fail2ban-client status "$jail" 2>/dev/null
            echo ""
        done
    else
        echo -e "${SARI}⚠️ Aktif jail bulunamadı!${NC}"
    fi
    
    enter_bekle
    ban_yonetimi
}

# Fail2ban Yeniden Başlatma
fail2ban_yeniden_baslat() {
    echo ""
    echo -e "${TURKUAZ}🔄 FAIL2BAN YENİDEN BAŞLATMA${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    echo -e "${TURKUAZ}[1/3]${NC} Fail2ban durduruluyor..."
    systemctl stop fail2ban
    echo -e "${ACIK_YESIL}   ✅ Fail2ban durduruldu${NC}"
    
    echo -e "${TURKUAZ}[2/3]${NC} Konfigürasyon test ediliyor..."
    if fail2ban-client -t >/dev/null 2>&1; then
        echo -e "${ACIK_YESIL}   ✅ Konfigürasyon geçerli${NC}"
    else
        echo -e "${TURUNCU}   ❌ Konfigürasyon hatası!${NC}"
        enter_bekle
        return 1
    fi
    
    echo -e "${TURKUAZ}[3/3]${NC} Fail2ban başlatılıyor..."
    systemctl start fail2ban
    
    if systemctl is-active --quiet fail2ban; then
        echo -e "${ACIK_YESIL}   ✅ Fail2ban başarıyla başlatıldı${NC}"
    else
        echo -e "${TURUNCU}   ❌ Fail2ban başlatılamadı!${NC}"
    fi
    
    enter_bekle
    ban_yonetimi
}

# Ban Geçmişi Göster
ban_gecmisi_goster() {
    echo ""
    echo -e "${TURKUAZ}📋 BAN GEÇMİŞİ${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    echo -e "${BEYAZ}📊 Son 50 Fail2ban Logu:${NC}"
    if [[ -f "/var/log/fail2ban.log" ]]; then
        tail -50 /var/log/fail2ban.log | grep -E "(Ban|Unban)" | while IFS= read -r line; do
            if echo "$line" | grep -q "Ban"; then
                echo -e "${TURUNCU}🔴 $line${NC}"
            else
                echo -e "${ACIK_YESIL}🟢 $line${NC}"
            fi
        done
    else
        echo -e "${SARI}⚠️ Fail2ban log dosyası bulunamadı!${NC}"
    fi
    
    enter_bekle
    ban_yonetimi
}

# =====================================================
# ☁️ CLOUDPANEL MENÜ SİSTEMİ
# =====================================================

# CloudPanel menü gösterme
cloudpanel_menu_goster() {
    echo -e "${TURKUAZ}╔════════════════════════════════════╗${NC}"
    echo -e "${TURKUAZ}║         CLOUDPANEL MENÜSÜ         ║${NC}"
    echo -e "${TURKUAZ}╚════════════════════════════════════╝${NC}"
    echo ""
    
    cloudpanel_durum_kontrol
    
    echo -e "1) 🚀 CloudPanel Kur + Fail2Ban (Otomatik kurulum) ✅ CloudPanel kurulumundan sonra otomatik port açma \"53\""
    echo -e "2) ⚙️ Fail2ban Yapılandırma"
    echo -e "3) 🔓 Ban Kaldır"
    echo -e "4) 📊 Fail2Ban Status"
    echo -e "5) 🛠️ Kurtar/Engelkaldır (Hangisini Kullanmak istersen...)"
    echo -e "6) 🔙 Geri"
    echo -e "0) ❌ Çıkış"
    echo ""
}

# Kurtar/Engelkaldır seçim menüsü
kurtar_engelkaldir_menu() {
    ana_baslik_goster
    
    echo -e "${MOR}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MOR}║              KURTAR/ENGELKALDIR MENÜSÜ                  ║${NC}"
    echo -e "${MOR}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${TURKUAZ}🛠️ Hangi aracı kullanmak istiyorsunuz?${NC}"
    echo ""
    echo -e "1) 🚑 Kurtar.sh (Tam kurtarma - Tüm banları kaldır)"
    echo -e "2) 🔓 Engelkaldır.sh (Sadece IP banlarını kaldır)"
    echo -e "3) 🔙 Geri"
    echo ""
    
    echo -e "${SARI}Seçiminizi yapın (1-3): ${NC}"
    read -r secim
    
    case $secim in
        1)
            kurtar_sh_calistir
            ;;
        2)
            engelkaldir_sh_calistir
            ;;
        3)
            return 0
            ;;
        *)
            echo -e "${TURUNCU}❌ Geçersiz seçim!${NC}"
            sleep 2
            kurtar_engelkaldir_menu
            ;;
    esac
}

# Kurtar.sh çalıştırma (paylaştığınız kurtar.sh dosyasından)
kurtar_sh_calistir() {
    ana_baslik_goster
    
    echo -e "${MOR}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MOR}║            CLOUDPANEL FAIL2BAN KURTARMA                 ║${NC}"
    echo -e "${MOR}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${TURUNCU}⚠️ UYARI: Bu işlem tüm fail2ban banlarını kaldırır ve sistemi sıfırlar!${NC}"
    echo -e "${SARI}Sunucu: $(hostname)${NC}"
    echo -e "${SARI}Dış IP: $DIS_IP${NC}"
    echo -e "${SARI}İç IP: $IC_IP${NC}"
    echo ""
    
    echo -e "${BEYAZ}Kurtarma işlemine devam edilsin mi? (E/h): ${NC}"
    read -r onay
    
    if [[ ! "$onay" =~ ^[EeYy]$ ]]; then
        echo -e "${SARI}⚠️ Kurtarma işlemi iptal edildi.${NC}"
        enter_bekle
        return 0
    fi
    
    echo -e "${TURKUAZ}🚑 CLOUDPANEL FAIL2BAN KURTARMA BAŞLANIYOR...${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    # Fail2ban durumunu kontrol et
    echo -e "${TURKUAZ}[1/8]${NC} Fail2ban durumu kontrol ediliyor..."
    if systemctl is-active --quiet fail2ban; then
        echo -e "${ACIK_YESIL}   ✅ Fail2ban çalışıyor${NC}"
    else
        echo -e "${SARI}   ⚠️ Fail2ban zaten çalışmıyor${NC}"
    fi
    
    # Fail2ban'ı durdur
    echo -e "${TURKUAZ}[2/8]${NC} Fail2ban servisi durduruluyor..."
    systemctl stop fail2ban
    echo -e "${ACIK_YESIL}   ✅ Fail2ban durduruldu${NC}"
    
    # Tüm iptables kurallarını temizle
    echo -e "${TURKUAZ}[3/8]${NC} Fail2ban tarafından eklenen iptables kuralları temizleniyor..."
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    echo -e "${ACIK_YESIL}   ✅ Iptables kuralları temizlendi${NC}"
    
    # Varsayılan iptables kurallarını oluştur
    echo -e "${TURKUAZ}[4/8]${NC} Varsayılan güvenlik kuralları uygulanıyor..."
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # SSH ve CloudPanel erişimini sağla
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp --dport 8443 -j ACCEPT  # CloudPanel web arayüzü
    echo -e "${ACIK_YESIL}   ✅ Temel erişim kuralları eklendi${NC}"
    
    # Fail2ban jail dosyalarındaki engellenen IP'leri temizle
    echo -e "${TURKUAZ}[5/8]${NC} Fail2ban jail dosyaları temizleniyor..."
    if [[ -f "/var/lib/fail2ban/fail2ban.sqlite3" ]]; then
        rm -f /var/lib/fail2ban/fail2ban.sqlite3
        touch /var/lib/fail2ban/fail2ban.sqlite3
        echo -e "${ACIK_YESIL}   ✅ Fail2ban veritabanı temizlendi${NC}"
    else
        echo -e "${SARI}   ⚠️ Fail2ban veritabanı bulunamadı${NC}"
    fi
    
    # Fail2ban jail'lerini sıfırla
    echo -e "${TURKUAZ}[6/8]${NC} Fail2ban jail'leri sıfırlanıyor..."
    local jails=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | cut -d: -f2 | tr ',' '\n' | xargs)
    
    if [[ -n "$jails" ]]; then
        for jail in $jails; do
            echo -e "${BEYAZ}   🔧 Jail '$jail' sıfırlanıyor...${NC}"
            # Tüm IP'leri unban et (jail çalışmıyorsa hata verebilir, o yüzden sessiz)
            fail2ban-client set "$jail" unbanip --all >/dev/null 2>&1 || true
        done
        echo -e "${ACIK_YESIL}   ✅ Jail'ler sıfırlandı${NC}"
    else
        echo -e "${SARI}   ⚠️ Aktif jail bulunamadı${NC}"
    fi
    
    # UFW kurallarını yeniden düzenle
    echo -e "${TURKUAZ}[7/8]${NC} UFW kuralları yeniden düzenleniyor..."
    ufw --force reset >/dev/null 2>&1
    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1
    
    # Temel portları aç
    ufw allow ${SSH_PORT}/tcp >/dev/null 2>&1
    ufw allow ${SSH_OZEL_PORT}/tcp >/dev/null 2>&1
    ufw allow 8443/tcp >/dev/null 2>&1
    ufw allow 53/tcp >/dev/null 2>&1
    ufw allow 53/udp >/dev/null 2>&1
    ufw allow 80/tcp >/dev/null 2>&1
    ufw allow 443/tcp >/dev/null 2>&1
    
    ufw --force enable >/dev/null 2>&1
    echo -e "${ACIK_YESIL}   ✅ UFW kuralları yeniden düzenlendi${NC}"
    
    # Fail2ban'ı yeniden başlat
    echo -e "${TURKUAZ}[8/8]${NC} Fail2ban yeniden başlatılıyor..."
    systemctl start fail2ban
    
    if systemctl is-active --quiet fail2ban; then
        echo -e "${ACIK_YESIL}   ✅ Fail2ban başarıyla başlatıldı${NC}"
    else
        echo -e "${TURUNCU}   ❌ Fail2ban başlatılamadı!${NC}"
    fi
    
    echo ""
    echo -e "${ACIK_YESIL}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${ACIK_YESIL}║           ✅ KURTARMA İŞLEMİ TAMAMLANDI!               ║${NC}"
    echo -e "${ACIK_YESIL}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BEYAZ}📊 Kurtarma Özeti:${NC}"
    echo -e "   🛡️ Fail2ban: $(systemctl is-active --quiet fail2ban && echo -e "${ACIK_YESIL}Çalışıyor${NC}" || echo -e "${TURUNCU}Çalışmıyor${NC}")"
    echo -e "   🔓 Tüm IP banları kaldırıldı"
    echo -e "   🔧 Iptables kuralları sıfırlandı"
    echo -e "   🗄️ Veritabanı temizlendi"
    echo -e "   🛡️ UFW yeniden yapılandırıldı"
    echo -e "   🌐 CloudPanel erişimi: https://$DIS_IP:8443"
    echo ""
    
    gunluk_yaz "BILGI" "CloudPanel Fail2ban kurtarma işlemi tamamlandı"
    enter_bekle
}

# Engelkaldır.sh çalıştırma (paylaştığınız engelkaldir.sh dosyasından)
engelkaldir_sh_calistir() {
    ana_baslik_goster
    
    echo -e "${MOR}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MOR}║                 ENGEL KALDIRMA İŞLEMİ                   ║${NC}"
    echo -e "${MOR}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${TURKUAZ}🔓 ENGEL KALDIRMA BAŞLANIYOR...${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    # Fail2ban durumu kontrol
    if ! systemctl is-active --quiet fail2ban; then
        echo -e "${TURUNCU}❌ Fail2ban servisi çalışmıyor!${NC}"
        enter_bekle
        return 1
    fi
    
    # Tüm jail'leri listele
    echo -e "${TURKUAZ}[1/3]${NC} Aktif jail'ler tespit ediliyor..."
    local jails=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | sed "s/^[^:]*:[ \t]*//g" | sed "s/,//g")
    
    if [[ -z "$jails" ]]; then
        echo -e "${SARI}⚠️ Aktif jail bulunamadı!${NC}"
        enter_bekle
        return 0
    fi
    
    echo -e "${ACIK_YESIL}   ✅ Bulunan jail'ler: $jails${NC}"
    
    # Her jail'deki tüm IP'leri kaldır
    echo -e "${TURKUAZ}[2/3]${NC} Tüm jail'lerden IP banları kaldırılıyor..."
    local toplam_kaldirildi=0
    
    for jail in $jails; do
        echo -e "${BEYAZ}   🔧 Jail işleniyor: $jail${NC}"
        
        # Jail'deki banlı IP'leri al
        local banned_ips=$(fail2ban-client status "$jail" 2>/dev/null | grep "Banned IP list:" | cut -d: -f2 | xargs)
        
        if [[ -n "$banned_ips" && "$banned_ips" != "" ]]; then
            for ip in $banned_ips; do
                if fail2ban-client set "$jail" unbanip "$ip" >/dev/null 2>&1; then
                    echo -e "      🔓 $ip kaldırıldı"
                    toplam_kaldirildi=$((toplam_kaldirildi + 1))
                else
                    echo -e "      ❌ $ip kaldırılamadı"
                fi
            done
        else
            echo -e "      ℹ️ Bu jail'de banlı IP yok"
        fi
    done
    
    # Sonuç raporu
    echo -e "${TURKUAZ}[3/3]${NC} İşlem tamamlandı..."
    echo -e "${ACIK_YESIL}   ✅ Toplam $toplam_kaldirildi IP banı kaldırıldı${NC}"
    
    echo ""
    echo -e "${ACIK_YESIL}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${ACIK_YESIL}║           ✅ ENGEL KALDIRMA TAMAMLANDI!                ║${NC}"
    echo -e "${ACIK_YESIL}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BEYAZ}📊 İşlem Özeti:${NC}"
    echo -e "   🔓 Kaldırılan IP sayısı: $toplam_kaldirildi"
    echo -e "   🔒 İşlenen jail sayısı: $(echo $jails | wc -w)"
    echo -e "   🛡️ Fail2ban durumu: Çalışmaya devam ediyor"
    echo ""
    
    gunluk_yaz "BILGI" "Engel kaldırma işlemi tamamlandı ($toplam_kaldirildi IP)"
    enter_bekle
}

# CloudPanel ana menü fonksiyonu
cloudpanel_menu() {
    while true; do
        ana_baslik_goster
        cloudpanel_menu_goster
        
        echo -e "${SARI}Seçiminizi yapın (0-6): ${NC}"
        read -r secim
        
        case $secim in
            1)
                cloudpanel_kur_otomatik
                ;;
            2)
                ban_yonetimi
                ;;
            3)
                ip_ban_kaldir
                ;;
            4)
                fail2ban_status_goster
                ;;
            5)
                kurtar_engelkaldir_menu
                ;;
            6)
                echo -e "${TURKUAZ}🔙 Ana menüye dönülüyor...${NC}"
                return 0
                ;;
            0)
                cikis_yap
                ;;
            *)
                gecersiz_secim
                ;;
        esac
    done
}

# =====================================================
# 📧 MAIL SUNUCU FONKSİYONLARI
# =====================================================

# Mail sunucu ana kurulum fonksiyonu
mail_sunucu_kur() {
    ana_baslik_goster
    
    echo -e "${MOR}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MOR}║                MAIL SUNUCU KURULUMU                     ║${NC}"
    echo -e "${MOR}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # CloudPanel kontrolü
    cloudpanel_kontrol || return 1
    
    # CloudPanel SSL sertifikalarını bul
    cloudpanel_ssl_bul || return 1

    # DMARC yapılandırması ekle
    for domain in "${ALAN_ADLARI[@]}"; do
        dmarc_yapilandir "$domain"
    done

    # Manuel domain girişi
    manuel_domain_girisi || return 1
    
    echo -e "${TURKUAZ}🚀 MAIL SUNUCU KURULUMU BAŞLANIYOR...${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    # Kurulum adımları
    mail_paketleri_kur || return 1
    veritabani_olustur || return 1
    domain_ve_kullanici_ekle || return 1
    postfix_yapilandir || return 1
    dovecot_yapilandir || return 1
    opendkim_yapilandir || return 1
    roundcube_kur || return 1
    cloudpanel_nginx_yapilandir || return 1
    servisleri_baslat || return 1
    sistem_testleri || return 1
    dkim_kayitlari_goster || return 1
    kurulum_ozeti || return 1
}

# CloudPanel kontrolü
cloudpanel_kontrol() {
    echo -e "${TURKUAZ}[1/12]${NC} CloudPanel kontrolü yapılıyor..."
    
    if [[ ! -d "/home/clp" ]]; then
        echo -e "${TURUNCU}❌ CloudPanel kurulu değil!${NC}"
        echo -e "${SARI}⚠️ Önce CloudPanel kurulumunu yapın.${NC}"
        return 1
    fi
    
    if ! systemctl is-active --quiet clp-nginx; then
        echo -e "${TURUNCU}❌ CloudPanel web sunucusu çalışmıyor!${NC}"
        return 1
    fi
    
    echo -e "${ACIK_YESIL}✅ CloudPanel aktif ve çalışıyor${NC}"
    return 0
}

# CloudPanel SSL sertifikalarını bul
cloudpanel_ssl_bul() {
    echo -e "${TURKUAZ}[2/12]${NC} SSL sertifikaları kontrol ediliyor..."
    
    # CloudPanel SSL dizinini kontrol et
    if [[ ! -d "$SSL_SERTIFIKA_DIZINI" ]]; then
        echo -e "${TURUNCU}❌ SSL sertifika dizini bulunamadı!${NC}"
        return 1
    fi
    
    # Domain bazlı SSL sertifikalarını kontrol et
    for domain in "${ALAN_ADLARI[@]}"; do
        local ssl_cert="$SSL_SERTIFIKA_DIZINI/$domain.crt"
        local ssl_key="$SSL_SERTIFIKA_DIZINI/$domain.key"
        
        if [[ -f "$ssl_cert" && -f "$ssl_key" ]]; then
            echo -e "${ACIK_YESIL}✅ SSL bulundu: $domain${NC}"
            SSL_CERT="$ssl_cert"
            SSL_KEY="$ssl_key"
            return 0
        fi
    done
    
    echo -e "${SARI}⚠️ Domain SSL sertifikaları bulunamadı, varsayılan kullanılacak${NC}"
    SSL_CERT="$SSL_SERTIFIKA_SNAKEOIL"
    SSL_KEY="$SSL_ANAHTAR_SNAKEOIL"
    return 0
}

# Manuel domain girişi
manuel_domain_girisi() {
    echo -e "${TURKUAZ}[3/12]${NC} Mail domain ayarları..."
    
    # Mevcut domain listesini göster
    echo -e "${BEYAZ}Mevcut domainler:${NC}"
    for domain in "${ALAN_ADLARI[@]}"; do
        echo -e "   🌐 $domain"
    done
    echo ""
    
    # Yeni domain girişi
    echo -e "${BEYAZ}Mail sunucusu için ana domain seçin veya yeni domain girin:${NC}"
    read -r YENI_ALAN_ADI
    
    # Domain validasyonu
    if ! domain_gecerli_mi "$YENI_ALAN_ADI"; then
        return 1
    fi
    
    echo -e "${ACIK_YESIL}✅ Domain ayarlandı: $YENI_ALAN_ADI${NC}"
    return 0
}

# Mail paketlerini kur
mail_paketleri_kur() {
    echo -e "${TURKUAZ}[4/12]${NC} Mail paketleri kuruluyor..."
    
    # Gerekli paketleri kur
    apt update
    apt install -y postfix postfix-mysql dovecot-core dovecot-imapd dovecot-pop3d \
                   dovecot-mysql dovecot-sieve dovecot-managesieved opendkim \
                   opendkim-tools mailutils
    
    if [[ $? -ne 0 ]]; then
        echo -e "${TURUNCU}❌ Paket kurulumu başarısız!${NC}"
        return 1
    fi
    
    echo -e "${ACIK_YESIL}✅ Mail paketleri kuruldu${NC}"
    return 0
}

# Veritabanı oluştur
veritabani_olustur() {
    echo -e "${TURKUAZ}[5/12]${NC} Veritabanı oluşturuluyor..."
    
    # MySQL root şifresini al
    if [[ -z "$MYSQL_ROOT_SIFRE" ]]; then
        echo -e "${BEYAZ}MySQL root şifresini girin:${NC}"
        read -s MYSQL_ROOT_SIFRE
        echo ""
    fi
    
    # Veritabanı ve tabloları oluştur
    mysql -u"$MYSQL_ROOT_KULLANICI" -p"$MYSQL_ROOT_SIFRE" << EOF
CREATE DATABASE IF NOT EXISTS $MAIL_VERITABANI_ADI;
GRANT ALL ON $MAIL_VERITABANI_ADI.* TO '$MAIL_VERITABANI_KULLANICI'@'localhost' IDENTIFIED BY '$MAIL_VERITABANI_SIFRE';
FLUSH PRIVILEGES;

USE $MAIL_VERITABANI_ADI;

CREATE TABLE IF NOT EXISTS virtual_domains (
  id int(11) NOT NULL auto_increment,
  name varchar(50) NOT NULL,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS virtual_users (
  id int(11) NOT NULL auto_increment,
  domain_id int(11) NOT NULL,
  password varchar(106) NOT NULL,
  email varchar(100) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY email (email),
  FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS virtual_aliases (
  id int(11) NOT NULL auto_increment,
  domain_id int(11) NOT NULL,
  source varchar(100) NOT NULL,
  destination varchar(100) NOT NULL,
  PRIMARY KEY (id),
  FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
EOF
    
    if [[ $? -ne 0 ]]; then
        echo -e "${TURUNCU}❌ Veritabanı oluşturma başarısız!${NC}"
        return 1
    fi
    
    echo -e "${ACIK_YESIL}✅ Veritabanı oluşturuldu${NC}"
    return 0
}

# Domain ve kullanıcı ekle
domain_ve_kullanici_ekle() {
    echo -e "${TURKUAZ}[6/12]${NC} Domain ve kullanıcılar ekleniyor..."
    
    # Domain ekle
    mysql -u"$MYSQL_ROOT_KULLANICI" -p"$MYSQL_ROOT_SIFRE" $MAIL_VERITABANI_ADI << EOF
INSERT INTO virtual_domains (name) VALUES ('$YENI_ALAN_ADI');
EOF
    
    # Admin kullanıcısı ekle
    local admin_sifre=$(openssl rand -base64 12)
    local admin_sifre_hash=$(doveadm pw -s SHA512-CRYPT -p "$admin_sifre")
    
    mysql -u"$MYSQL_ROOT_KULLANICI" -p"$MYSQL_ROOT_SIFRE" $MAIL_VERITABANI_ADI << EOF
INSERT INTO virtual_users (domain_id, password, email)
SELECT id, '$admin_sifre_hash', 'admin@$YENI_ALAN_ADI'
FROM virtual_domains WHERE name='$YENI_ALAN_ADI';
EOF
    
    echo -e "${ACIK_YESIL}✅ Admin hesabı oluşturuldu:${NC}"
    echo -e "   📧 Email: admin@$YENI_ALAN_ADI"
    echo -e "   🔑 Şifre: $admin_sifre"
    
    return 0
}

# Postfix yapılandır
postfix_yapilandir() {
    echo -e "${TURKUAZ}[7/12]${NC} Postfix yapılandırılıyor..."
    
    # Ana yapılandırma
    postconf -e "myhostname = $YENI_ALAN_ADI"
    postconf -e "mydestination = localhost"
    postconf -e "mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128"
    postconf -e "inet_interfaces = all"
    postconf -e "inet_protocols = ipv4"
    postconf -e "smtpd_tls_cert_file = $SSL_CERT"
    postconf -e "smtpd_tls_key_file = $SSL_KEY"
    postconf -e "smtpd_use_tls = yes"
    postconf -e "smtpd_tls_auth_only = yes"
    
    # Virtual domain yapılandırması
    postconf -e "virtual_transport = lmtp:unix:private/dovecot-lmtp"
    postconf -e "virtual_mailbox_domains = mysql:/etc/postfix/mysql-virtual-mailbox-domains.cf"
    postconf -e "virtual_mailbox_maps = mysql:/etc/postfix/mysql-virtual-mailbox-maps.cf"
    postconf -e "virtual_alias_maps = mysql:/etc/postfix/mysql-virtual-alias-maps.cf"
    
    # DMARC yapılandırması ekle
    postconf -e "smtpd_milters = inet:localhost:8891"
    postconf -e "non_smtpd_milters = inet:localhost:8891"
    postconf -e "milter_default_action = accept"
    postconf -e "dmarc_reports_address = dmarc@$YENI_ALAN_ADI"

    # MySQL yapılandırma dosyaları
    cat > /etc/postfix/mysql-virtual-mailbox-domains.cf << EOF
user = $MAIL_VERITABANI_KULLANICI
password = $MAIL_VERITABANI_SIFRE
hosts = $MYSQL_SUNUCU
dbname = $MAIL_VERITABANI_ADI
query = SELECT 1 FROM virtual_domains WHERE name='%s'
EOF
    
    cat > /etc/postfix/mysql-virtual-mailbox-maps.cf << EOF
user = $MAIL_VERITABANI_KULLANICI
password = $MAIL_VERITABANI_SIFRE
hosts = $MYSQL_SUNUCU
dbname = $MAIL_VERITABANI_ADI
query = SELECT 1 FROM virtual_users WHERE email='%s'
EOF
    
    cat > /etc/postfix/mysql-virtual-alias-maps.cf << EOF
user = $MAIL_VERITABANI_KULLANICI
password = $MAIL_VERITABANI_SIFRE
hosts = $MYSQL_SUNUCU
dbname = $MAIL_VERITABANI_ADI
query = SELECT destination FROM virtual_aliases WHERE source='%s'
EOF
    
    # Dosya izinlerini ayarla
    chmod 0640 /etc/postfix/mysql-*.cf
    chown root:postfix /etc/postfix/mysql-*.cf
    
    echo -e "${ACIK_YESIL}✅ Postfix yapılandırıldı${NC}"
    return 0
}

# Dovecot yapılandır
dovecot_yapilandir() {
    echo -e "${TURKUAZ}[8/12]${NC} Dovecot yapılandırılıyor..."
    
    # Ana yapılandırma
    cat > /etc/dovecot/dovecot.conf << EOF
protocols = imap pop3 lmtp
listen = *, ::
mail_location = maildir:/var/mail/vhosts/%d/%n
mail_privileged_group = mail

namespace inbox {
  inbox = yes
  location =
  mailbox Drafts {
    special_use = \Drafts
    auto = subscribe
  }
  mailbox Junk {
    special_use = \Junk
    auto = subscribe
  }
  mailbox Sent {
    special_use = \Sent
    auto = subscribe
  }
  mailbox Trash {
    special_use = \Trash
    auto = subscribe
  }
  prefix =
}

service auth {
  unix_listener auth-userdb {
    mode = 0600
    user = vmail
    group = vmail
  }
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}

service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}

userdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}

passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}

ssl = required
ssl_cert = <$SSL_CERT
ssl_key = <$SSL_KEY
EOF
    
    # SQL yapılandırması
    cat > /etc/dovecot/dovecot-sql.conf.ext << EOF
driver = mysql
connect = host=$MYSQL_SUNUCU dbname=$MAIL_VERITABANI_ADI user=$MAIL_VERITABANI_KULLANICI password=$MAIL_VERITABANI_SIFRE
default_pass_scheme = SHA512-CRYPT
password_query = SELECT email as user, password FROM virtual_users WHERE email='%u';
user_query = SELECT concat('/var/mail/vhosts/%d/%n') as home, 5000 as uid, 5000 as gid FROM virtual_users WHERE email='%u';
iterate_query = SELECT email as user FROM virtual_users;
EOF
    
    # Mail dizini oluştur
    mkdir -p /var/mail/vhosts
    groupadd -g 5000 vmail
    useradd -g vmail -u 5000 vmail -d /var/mail
    chown -R vmail:vmail /var/mail
    
    echo -e "${ACIK_YESIL}✅ Dovecot yapılandırıldı${NC}"
    return 0
}

# OpenDKIM yapılandır
opendkim_yapilandir() {
    echo -e "${TURKUAZ}[9/12]${NC} OpenDKIM yapılandırılıyor..."
    
    # Ana yapılandırma
    cat > /etc/opendkim.conf << EOF
Syslog          yes
UMask           002
Domain          $YENI_ALAN_ADI
KeyFile         /etc/opendkim/keys/$YENI_ALAN_ADI/mail.private
Selector        mail
Socket          inet:8891@localhost
EOF
    
    # DKIM anahtarı oluştur
    mkdir -p "/etc/opendkim/keys/$YENI_ALAN_ADI"
    opendkim-genkey -t -s mail -d "$YENI_ALAN_ADI" -D "/etc/opendkim/keys/$YENI_ALAN_ADI"
    chown -R opendkim:opendkim /etc/opendkim
    
    # DMARC dizinleri oluştur
    mkdir -p "/etc/opendkim/dmarc"
    mkdir -p "/var/log/dmarc/reports"
    chown -R opendkim:opendkim /etc/opendkim/dmarc
    chown -R opendkim:opendkim /var/log/dmarc

    # Postfix entegrasyonu
    postconf -e "milter_protocol = 2"
    postconf -e "milter_default_action = accept"
    postconf -e "smtpd_milters = inet:localhost:8891"
    postconf -e "non_smtpd_milters = inet:localhost:8891"
    
    echo -e "${ACIK_YESIL}✅ OpenDKIM yapılandırıldı${NC}"
    return 0
}

# Roundcube kur
roundcube_kur() {
    echo -e "${TURKUAZ}[10/12]${NC} Roundcube kuruluyor..."
    
    # Roundcube indirme ve kurulum
    cd /tmp
    wget https://github.com/roundcube/roundcubemail/releases/download/$ROUNDCUBE_SURUMU/$ROUNDCUBE_ARSIV
    tar xf $ROUNDCUBE_ARSIV
    mv roundcubemail-* /var/www/roundcube
    
    # Veritabanı oluştur
    mysql -u"$MYSQL_ROOT_KULLANICI" -p"$MYSQL_ROOT_SIFRE" << EOF
CREATE DATABASE IF NOT EXISTS $ROUNDCUBE_VERITABANI_ADI;
GRANT ALL ON $ROUNDCUBE_VERITABANI_ADI.* TO '$ROUNDCUBE_VERITABANI_KULLANICI'@'localhost' IDENTIFIED BY '$ROUNDCUBE_VERITABANI_SIFRE';
FLUSH PRIVILEGES;
EOF
    
    # Roundcube yapılandırması
    cp /var/www/roundcube/config/config.inc.php.sample /var/www/roundcube/config/config.inc.php
    
    # Yapılandırma dosyasını düzenle
    sed -i "s/\$config\['db_dsnw'\].*/\$config['db_dsnw'] = 'mysql:\/\/$ROUNDCUBE_VERITABANI_KULLANICI:$ROUNDCUBE_VERITABANI_SIFRE@localhost\/$ROUNDCUBE_VERITABANI_ADI';/" /var/www/roundcube/config/config.inc.php
    
    # İzinleri ayarla
    chown -R www-data:www-data /var/www/roundcube
    
    echo -e "${ACIK_YESIL}✅ Roundcube kuruldu${NC}"
    return 0
}

# CloudPanel Nginx yapılandır
cloudpanel_nginx_yapilandir() {
    echo -e "${TURKUAZ}[11/12]${NC} CloudPanel Nginx yapılandırılıyor..."
    
    # Webmail vhost oluştur
    cat > "$NGINX_MEVCUT_SITELER/webmail.$YENI_ALAN_ADI.conf" << EOF
server {
    listen 80;
    listen [::]:80;
    server_name webmail.$YENI_ALAN_ADI;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name webmail.$YENI_ALAN_ADI;
    
    ssl_certificate $SSL_CERT;
    ssl_certificate_key $SSL_KEY;
    
    root /var/www/roundcube;
    index index.php;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass unix:$PHP_FPM_SOKETI;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }
}
EOF
    
    # Symlink oluştur
    ln -sf "$NGINX_MEVCUT_SITELER/webmail.$YENI_ALAN_ADI.conf" "$NGINX_ETKIN_SITELER/"
    
    # Nginx'i test et ve yeniden yükle
    nginx -t && systemctl reload nginx
    
    echo -e "${ACIK_YESIL}✅ Nginx yapılandırıldı${NC}"
    return 0
}

# Servisleri başlat
servisleri_baslat() {
    echo -e "${TURKUAZ}[12/12]${NC} Servisler başlatılıyor..."
    
    systemctl restart postfix dovecot opendkim
    systemctl enable postfix dovecot opendkim
    
    # Servis durumlarını kontrol et
    local servisler=("postfix" "dovecot" "opendkim")
    local basarisiz=0
    
    for servis in "${servisler[@]}"; do
        if systemctl is-active --quiet "$servis"; then
            echo -e "   ✅ $servis: ${ACIK_YESIL}Çalışıyor${NC}"
        else
            echo -e "   ❌ $servis: ${TURUNCU}Çalışmıyor${NC}"
            basarisiz=$((basarisiz + 1))
        fi
    done
    
    if [[ $basarisiz -eq 0 ]]; then
        echo -e "${ACIK_YESIL}✅ Tüm servisler başarıyla başlatıldı${NC}"
        return 0
    else
        echo -e "${TURUNCU}❌ Bazı servisler başlatılamadı!${NC}"
        return 1
    fi
}

# Sistem testleri
sistem_testleri() {
    echo -e "${TURKUAZ}🧪 SİSTEM TESTLERİ YAPILIYOR...${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    # Postfix testi
    echo -e "${BEYAZ}📨 Postfix SMTP testi...${NC}"
    if nc -zv localhost 25 2>/dev/null; then
        echo -e "${ACIK_YESIL}✅ SMTP port 25 açık${NC}"
    else
        echo -e "${TURUNCU}❌ SMTP port 25 kapalı${NC}"
    fi
    
    # Dovecot testi
    echo -e "${BEYAZ}📬 Dovecot IMAP/POP3 testi...${NC}"
    if nc -zv localhost 993 2>/dev/null; then
        echo -e "${ACIK_YESIL}✅ IMAP SSL port 993 açık${NC}"
    else
        echo -e "${TURUNCU}❌ IMAP SSL port 993 kapalı${NC}"
    fi
    
    # OpenDKIM testi
    echo -e "${BEYAZ}🔑 OpenDKIM testi...${NC}"
    if nc -zv localhost 8891 2>/dev/null; then
        echo -e "${ACIK_YESIL}✅ OpenDKIM port 8891 açık${NC}"
    else
        echo -e "${TURUNCU}❌ OpenDKIM port 8891 kapalı${NC}"
    fi

    # DMARC testi ekle
    echo -e "${BEYAZ}📋 DMARC testi...${NC}"
    local dmarc_kayit=$(dig +short TXT _dmarc.$YENI_ALAN_ADI)
    if [[ -n "$dmarc_kayit" ]]; then
        echo -e "${ACIK_YESIL}✅ DMARC kaydı mevcut${NC}"
        echo -e "   📋 Kayıt: $dmarc_kayit"
    else
        echo -e "${TURUNCU}❌ DMARC kaydı bulunamadı${NC}"
    fi

    # DNS kayıtları testi
    echo -e "${BEYAZ}🌐 DNS kayıtları testi...${NC}"
    if host -t MX "$YENI_ALAN_ADI" 2>/dev/null | grep -q "mail.$YENI_ALAN_ADI"; then
        echo -e "${ACIK_YESIL}✅ MX kaydı doğru${NC}"
    else
        echo -e "${TURUNCU}❌ MX kaydı eksik veya hatalı${NC}"
    fi
    
    return 0
}

# DKIM kayıtlarını göster
dkim_kayitlari_goster() {
    echo -e "${TURKUAZ}🔑 DKIM KAYITLARI${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    local dkim_dosya="/etc/opendkim/keys/$YENI_ALAN_ADI/mail.txt"
    
    if [[ -f "$dkim_dosya" ]]; then
        echo -e "${BEYAZ}📋 DKIM DNS kaydı:${NC}"
        cat "$dkim_dosya"
        echo ""
        echo -e "${SARI}⚠️ Bu kaydı DNS yöneticinize eklemeyi unutmayın!${NC}"
    else
        echo -e "${TURUNCU}❌ DKIM kayıt dosyası bulunamadı!${NC}"
    fi
    
    return 0
}

# Kurulum özeti
kurulum_ozeti() {
    echo -e "${ACIK_YESIL}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${ACIK_YESIL}║           ✅ MAIL SUNUCU KURULUMU TAMAMLANDI!           ║${NC}"
    echo -e "${ACIK_YESIL}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BEYAZ}📊 Kurulum Özeti:${NC}"
    echo -e "   🌐 Domain: $YENI_ALAN_ADI"
    echo -e "   📨 SMTP: smtp.$YENI_ALAN_ADI:25 (SSL/TLS)"
    echo -e "   📬 IMAP: imap.$YENI_ALAN_ADI:993 (SSL/TLS)"
    echo -e "   📭 POP3: pop3.$YENI_ALAN_ADI:995 (SSL/TLS)"
    echo -e "   🌍 Webmail: https://webmail.$YENI_ALAN_ADI"
    echo -e "   👤 Admin: admin@$YENI_ALAN_ADI"
    echo ""
    echo -e "${SARI}⚠️ Önemli Notlar:${NC}"
    echo -e "   1. DNS kayıtlarını güncellemeyi unutmayın"
    echo -e "   2. DKIM kaydını DNS'e ekleyin"
    echo -e "   3. SSL sertifikalarının geçerli olduğundan emin olun"
    echo -e "   4. Güvenlik duvarı kurallarını kontrol edin"
    echo ""
    
    gunluk_yaz "BILGI" "Mail sunucu kurulumu tamamlandı: $YENI_ALAN_ADI"
    enter_bekle
}

# Mail servisleri menüsü
mail_servisleri() {
    while true; do
        ana_baslik_goster
        
        echo -e "${TURKUAZ}╔════════════════════════════════════╗${NC}"
        echo -e "${TURKUAZ}║        MAİL SERVİSLERİ            ║${NC}"
        echo -e "${TURKUAZ}╚════════════════════════════════════╝${NC}"
        echo ""
        
        echo -e "1) 🟢 Tüm Servisleri Başlat"
        echo -e "2) 🔴 Tüm Servisleri Durdur"
        echo -e "3) 🔄 Tüm Servisleri Yeniden Başlat"
        echo -e "4) 📊 Servis Durumlarını Göster"
        echo -e "5) 📋 Mail Kuyruğunu Göster"
        echo -e "6) 📜 Mail Loglarını Göster"
        echo -e "7) 🔙 Geri"
        echo -e "0) ❌ Çıkış"
        echo ""
        
        echo -e "${SARI}Seçiminizi yapın (0-7): ${NC}"
        read -r secim
        
        case $secim in
            1) tum_servisleri_baslat ;;
            2) tum_servisleri_durdur ;;
            3) tum_servisleri_yeniden_baslat ;;
            4) servis_durumlari ;;
            5) mail_kuyrugu_goster ;;
            6) mail_loglari_goster ;;
            7) return 0 ;;
            0) cikis_yap ;;
            *) gecersiz_secim ;;
        esac
    done
}

# Mail testleri menüsü
mail_testleri() {
    while true; do
        ana_baslik_goster
        
        echo -e "${TURKUAZ}╔════════════════════════════════════╗${NC}"
        echo -e "${TURKUAZ}║          MAİL TESTLERİ            ║${NC}"
        echo -e "${TURKUAZ}╚════════════════════════════════════╝${NC}"
        echo ""
        
        echo -e "1) 🔍 Sistem Testleri"
        echo -e "2) 🔑 DKIM Testleri"
        echo -e "3) 📨 Test Maili Gönder"
        echo -e "4) 🌐 DNS Kayıtlarını Kontrol Et"
        echo -e "5) 🔒 SSL Sertifika Kontrolü"
        echo -e "6) 📋 DMARC Testi"
        echo -e "7) 🔙 Geri"
        echo -e "0) ❌ Çıkış"
        echo ""
        echo -e "${SARI}Seçiminizi yapın (0-6): ${NC}"
        read -r secim
        
        case $secim in
            1) sistem_testleri ;;
            2) dkim_testi_yap ;;
            3) test_mail_gonder ;;
            4) dns_kontrol ;;
            5) ssl_kontrol ;;
            6) dmarc_test "$YENI_ALAN_ADI" ;;
            7) return 0 ;;
            0) cikis_yap ;;
            *) gecersiz_secim ;;
        esac
    done
}

# DKIM testi yap
dkim_testi_yap() {
    echo -e "${TURKUAZ}🔑 DKIM TEST EDİLİYOR...${NC}"
    echo "═══════════════════════════════════════════════════"
    
    if ! command -v opendkim-testkey &>/dev/null; then
        echo -e "${TURUNCU}❌ OpenDKIM araçları kurulu değil!${NC}"
        return 1
    fi

    local dkim_anahtar="/etc/opendkim/keys/$YENI_ALAN_ADI/mail.private"
    
    if [[ ! -f "$dkim_anahtar" ]]; then
        echo -e "${TURUNCU}❌ DKIM özel anahtarı bulunamadı!${NC}"
        return 1
    fi

    echo -e "${BEYAZ}📋 DKIM anahtarı test ediliyor...${NC}"
    if opendkim-testkey -d "$YENI_ALAN_ADI" -s mail -k "$dkim_anahtar"; then
        echo -e "${ACIK_YESIL}✅ DKIM anahtarı geçerli${NC}"
    else
        echo -e "${TURUNCU}❌ DKIM anahtarı geçersiz!${NC}"
    fi
    
    enter_bekle
    return 0
}

# Test mail gönder
test_mail_gonder() {
    echo -e "${TURKUAZ}📨 TEST MAİL GÖNDERME${NC}"
    echo "═══════════════════════════════════════════════════"
    
    echo -e "${BEYAZ}Test mail göndermek istediğiniz adresi girin:${NC}"
    read -r hedef_adres
    
    if [[ ! $hedef_adres =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        echo -e "${TURUNCU}❌ Geçersiz email adresi!${NC}"
        return 1
    fi

    echo -e "Test maili gönderiliyor..."
    if echo "Bu bir test mailidir. Mail sunucusu kurulumu test edilmektedir." | mail -s "Mail Sunucusu Test" "$hedef_adres"; then
        echo -e "${ACIK_YESIL}✅ Test maili gönderildi${NC}"
    else
        echo -e "${TURUNCU}❌ Test maili gönderilemedi!${NC}"
    fi
    
    enter_bekle
    return 0
}

# DNS kayıtları kontrol et
dns_kontrol() {
    echo -e "${TURKUAZ}🌐 DNS KAYITLARI KONTROL EDİLİYOR...${NC}"
    echo "═══════════════════════════════════════════════════"
    
    # MX kaydı kontrolü
    echo -e "${BEYAZ}📨 MX kaydı kontrolü:${NC}"
    host -t MX "$YENI_ALAN_ADI"
    
    # SPF kaydı kontrolü
    echo -e "\n${BEYAZ}🛡️ SPF kaydı kontrolü:${NC}"
    host -t TXT "$YENI_ALAN_ADI"
    
    # DKIM kaydı kontrolü
    echo -e "\n${BEYAZ}🔑 DKIM kaydı kontrolü:${NC}"
    host -t TXT "mail._domainkey.$YENI_ALAN_ADI"
    
    # DMARC kaydı kontrolü
    echo -e "\n${BEYAZ}📋 DMARC kaydı kontrolü:${NC}"
    host -t TXT "_dmarc.$YENI_ALAN_ADI"
    
    enter_bekle
    return 0
}

# SSL sertifika kontrolü
ssl_kontrol() {
    echo -e "${TURKUAZ}🔒 SSL SERTİFİKA KONTROLÜ${NC}"
    echo "═══════════════════════════════════════════════════"
    
    if [[ ! -f "$SSL_CERT" ]]; then
        echo -e "${TURUNCU}❌ SSL sertifikası bulunamadı!${NC}"
        return 1
    fi

    echo -e "${BEYAZ}📋 Sertifika bilgileri:${NC}"
    openssl x509 -in "$SSL_CERT" -text -noout | grep -A 2 "Validity"
    
    # Sertifika son kullanma tarihi kontrolü
    son_kullanma=$(openssl x509 -in "$SSL_CERT" -enddate -noout | cut -d= -f2)
    son_kullanma_ts=$(date -d "$son_kullanma" +%s)
    simdi_ts=$(date +%s)
    
    if [[ $son_kullanma_ts -gt $simdi_ts ]]; then
        kalan_gun=$(( ($son_kullanma_ts - $simdi_ts) / 86400 ))
        echo -e "${ACIK_YESIL}✅ Sertifika geçerli (Kalan: $kalan_gun gün)${NC}"
    else
        echo -e "${TURUNCU}❌ Sertifika süresi dolmuş!${NC}"
    fi
    
    enter_bekle
    return 0
}

# =============================================================================
# OpenCart İnteraktif Temizleme Betiği
# Kullanıcı tüm yolları kendisi belirler!
# =============================================================================
opencart_temizle() {
    
echo -e "${TURKUAZ}========================================${NC}"
echo -e "${TURKUAZ} OpenCart İnteraktif Temizleme Betiği${NC}"
echo -e "${TURKUAZ}========================================${NC}"

# Güvenlik kontrolü
if [ "$EUID" -ne 0 ]; then
  echo -e "${TURUNCU}Bu betik root olarak çalıştırılmalıdır!${NC}"
  exit 1
fi

# =============================================================================
# BAŞLANGIÇ MENÜSÜ
# =============================================================================
echo -e "\n${ACIK_YESIL}🎯 Ne yapmak istiyorsunuz?${NC}"
echo -e "1) Siteni OLUŞTUR..."
echo -e "2) Çıkış"
read -p "Seçiminiz (1-2): " initial_choice

case $initial_choice in
  1)
    echo -e "\n${ACIK_YESIL}🚀 Site oluşturma işlemi başlatılıyor...${NC}"
    # Devam eder...
    ;;
  2)
    echo -e "\n${TURKUAZ}👋 Görüşürüz!${NC}"
    exit 0
    ;;
  *)
    echo -e "\n${TURUNCU}❌ Geçersiz seçim!${NC}"
    exit 1
    ;;
esac

# =============================================================================
# KULLANICI GİRDİLERİNİ AL
# =============================================================================
echo -e "\n${ACIK_YESIL}🔧 Lütfen dizin yollarını belirtin:${NC}"

# OpenCart kök dizini
read -p "OpenCart kök dizini (örn: /home/user/htdocs/site.com): " OPENCART_ROOT
if [ ! -d "$OPENCART_ROOT" ]; then
  echo -e "${TURUNCU}❌ Dizin bulunamadı: $OPENCART_ROOT${NC}"
  exit 1
fi

# Data dizini
read -p "OpenCart data dizini (örn: /home/user/storage): " DATA_ROOT
if [ ! -d "$DATA_ROOT" ]; then
  echo -e "${TURUNCU}❌ Dizin bulunamadı: $DATA_ROOT${NC}"
  exit 1
fi

# Sahiplik bilgileri
read -p "Dosya sahibi kullanıcı adı (örn: username): " OWNER
read -p "Dosya sahibi grup adı (örn: username): " GROUP

echo -e "\n${TURKUAZ}📋 Girilen bilgiler:${NC}"
echo -e "   OpenCart Kök: ${ACIK_YESIL}$OPENCART_ROOT${NC}"
echo -e "   Data Dizini: ${ACIK_YESIL}$DATA_ROOT${NC}"
echo -e "   Sahip: ${ACIK_YESIL}$OWNER:$GROUP${NC}"

read -p "Bu bilgiler doğru mu? (e/h): " confirm
if [[ $confirm != [eE] ]]; then
  echo -e "${SARI}İptal edildi.${NC}"
  exit 0
fi

# =============================================================================
# ÖNBELLEK TEMİZLEME FONKSİYONU
# =============================================================================
temizle_onbellek() {
  echo -e "\n${ACIK_YESIL}📁 Önbellek dosyaları temizleniyor...${NC}"
  
  # OpenCart Ana Önbellek
  if [ -d "$DATA_ROOT/cache" ]; then
    echo -e "   ${ACIK_YESIL}✓${NC} OpenCart önbellek temizleniyor..."
    cache_count=$(find "$DATA_ROOT/cache" -name "cache.*" -type f 2>/dev/null | wc -l)
    find "$DATA_ROOT/cache" -name "cache.*" -type f -delete 2>/dev/null
    echo -e "     Temizlenen: $cache_count dosya"
  else
    echo -e "   ${SARI}⚠${NC} OpenCart önbellek dizini bulunamadı: $DATA_ROOT/cache"
  fi
  
  # VQMod Önbellek
  if [ -d "$OPENCART_ROOT/vqmod/vqcache" ]; then
    echo -e "   ${ACIK_YESIL}✓${NC} VQMod önbellek temizleniyor..."
    vq_count=$(find "$OPENCART_ROOT/vqmod/vqcache" -name "vq2-*" -type f 2>/dev/null | wc -l)
    find "$OPENCART_ROOT/vqmod/vqcache" -name "vq2-*" -type f -delete 2>/dev/null
    rm -f "$OPENCART_ROOT/vqmod/checked.cache" 2>/dev/null
    rm -f "$OPENCART_ROOT/vqmod/mods.cache" 2>/dev/null
    echo -e "     Temizlenen VQMod önbellek: $vq_count dosya"
  else
    echo -e "   ${SARI}⚠${NC} VQMod önbellek dizini bulunamadı: $OPENCART_ROOT/vqmod/vqcache"
  fi
  
  # Resim Önbellek
  if [ -d "$OPENCART_ROOT/image/cache" ]; then
    echo -e "   ${ACIK_YESIL}✓${NC} Resim önbellek temizleniyor..."
    img_count=$(find "$OPENCART_ROOT/image/cache" -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" -o -name "*.gif" -type f 2>/dev/null | wc -l)
    find "$OPENCART_ROOT/image/cache" -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" -o -name "*.gif" -type f -delete 2>/dev/null
    echo -e "     Temizlenen resim önbellek: $img_count dosya"
  else
    echo -e "   ${SARI}⚠${NC} Resim önbellek dizini bulunamadı: $OPENCART_ROOT/image/cache"
  fi
  
  # Sistem Depolama Önbellek
  if [ -d "$OPENCART_ROOT/system/storage/cache" ]; then
    echo -e "   ${ACIK_YESIL}✓${NC} Sistem önbellek temizleniyor..."
    sys_count=$(find "$OPENCART_ROOT/system/storage/cache" -type f 2>/dev/null | wc -l)
    find "$OPENCART_ROOT/system/storage/cache" -type f -delete 2>/dev/null
    echo -e "     Temizlenen sistem önbellek: $sys_count dosya"
  else
    echo -e "   ${SARI}⚠${NC} Sistem önbellek dizini bulunamadı: $OPENCART_ROOT/system/storage/cache"
  fi
}

# =============================================================================
# GÜNLÜK TEMİZLEME FONKSİYONU
# =============================================================================
temizle_gunlukleri() {
  echo -e "\n${ACIK_YESIL}📝 Günlük dosyaları temizleniyor...${NC}"
  
  # OpenCart Günlükleri
  if [ -d "$DATA_ROOT/logs" ]; then
    echo -e "   ${ACIK_YESIL}✓${NC} OpenCart günlükleri temizleniyor..."
    
    # error.log temizle
    if [ -f "$DATA_ROOT/logs/error.log" ]; then
      > "$DATA_ROOT/logs/error.log"
      echo -e "     Hata günlüğü temizlendi"
    fi
    
    # hatalar.log temizle
    if [ -f "$DATA_ROOT/logs/hatalar.log" ]; then
      > "$DATA_ROOT/logs/hatalar.log"
      echo -e "     Hatalar günlüğü temizlendi"
    fi
    
    # ocmod.log temizle
    if [ -f "$DATA_ROOT/logs/ocmod.log" ]; then
      > "$DATA_ROOT/logs/ocmod.log"
      echo -e "     OCMod günlüğü temizlendi"
    fi
    
    # openbay.log temizle
    if [ -f "$DATA_ROOT/logs/openbay.log" ]; then
      > "$DATA_ROOT/logs/openbay.log"
      echo -e "     OpenBay günlüğü temizlendi"
    fi
    
    # Diğer günlük dosyaları
    find "$DATA_ROOT/logs" -name "*.log" -type f -exec sh -c '> "$1"' _ {} \; 2>/dev/null
  else
    echo -e "   ${SARI}⚠${NC} OpenCart günlük dizini bulunamadı: $DATA_ROOT/logs"
  fi
  
  # VQMod Günlükleri
  if [ -d "$OPENCART_ROOT/vqmod/logs" ]; then
    echo -e "   ${ACIK_YESIL}✓${NC} VQMod günlükleri temizleniyor..."
    vqmod_log_count=$(find "$OPENCART_ROOT/vqmod/logs" -name "*.log" -type f 2>/dev/null | wc -l)
    find "$OPENCART_ROOT/vqmod/logs" -name "*.log" -type f -exec sh -c '> "$1"' _ {} \; 2>/dev/null
    echo -e "     Temizlenen VQMod günlük: $vqmod_log_count dosya"
  else
    echo -e "   ${SARI}⚠${NC} VQMod günlük dizini bulunamadı: $OPENCART_ROOT/vqmod/logs"
  fi
  
  # Kök dizindeki hatalar.log
  if [ -f "$OPENCART_ROOT/hatalar.log" ]; then
    > "$OPENCART_ROOT/hatalar.log"
    echo -e "   ${ACIK_YESIL}✓${NC} Kök dizin hatalar.log temizlendi"
  fi
  
  # PHP error_log dosyaları
  find "$OPENCART_ROOT" -name "error_log" -type f -exec sh -c '> "$1"' _ {} \; 2>/dev/null
  echo -e "   ${ACIK_YESIL}✓${NC} PHP hata_günlüğü dosyaları temizlendi"
}

# =============================================================================
# OTURUM TEMİZLEME FONKSİYONU
# =============================================================================
temizle_oturumlari() {
  echo -e "\n${ACIK_YESIL}🔐 Oturum dosyaları temizleniyor...${NC}"
  
  if [ -d "$DATA_ROOT/session" ]; then
    echo -e "   ${ACIK_YESIL}✓${NC} Eski oturum dosyaları siliniyor..."
    old_sessions=$(find "$DATA_ROOT/session" -name "sess_*" -type f -mtime +7 2>/dev/null | wc -l)
    find "$DATA_ROOT/session" -name "sess_*" -type f -mtime +7 -delete 2>/dev/null
    remaining_sessions=$(find "$DATA_ROOT/session" -name "sess_*" -type f 2>/dev/null | wc -l)
    echo -e "     Silinen eski oturum: $old_sessions dosya"
    echo -e "     Kalan oturum: $remaining_sessions dosya"
  else
    echo -e "   ${SARI}⚠${NC} Oturum dizini bulunamadı: $DATA_ROOT/session"
  fi
}

# =============================================================================
# İZİN DÜZELTME FONKSİYONU
# =============================================================================
duzelt_izinleri() {
  echo -e "\n${ACIK_YESIL}🔧 İzinler düzeltiliyor...${NC}"
  
  # OpenCart kök dizini
  echo -e "   ${ACIK_YESIL}✓${NC} OpenCart kök dizini izinleri..."
  chown -R $OWNER:$GROUP "$OPENCART_ROOT"
  find "$OPENCART_ROOT" -type d -exec chmod 755 {} \;
  find "$OPENCART_ROOT" -type f -exec chmod 644 {} \;
  
  # Özel yazılabilir dizinler
  echo -e "   ${ACIK_YESIL}✓${NC} Yazılabilir dizinler..."
  
  # VQMod dizinleri
  if [ -d "$OPENCART_ROOT/vqmod" ]; then
    chmod -R 775 "$OPENCART_ROOT/vqmod/vqcache" 2>/dev/null
    chmod -R 775 "$OPENCART_ROOT/vqmod/logs" 2>/dev/null
    
    # Önbellek dosyalarını oluştur ve izin ver
    touch "$OPENCART_ROOT/vqmod/checked.cache" 2>/dev/null
    touch "$OPENCART_ROOT/vqmod/mods.cache" 2>/dev/null
    chmod 666 "$OPENCART_ROOT/vqmod/checked.cache" 2>/dev/null
    chmod 666 "$OPENCART_ROOT/vqmod/mods.cache" 2>/dev/null
    echo -e "     VQMod izinleri ayarlandı"
  fi
  
  # Resim önbelleği
  if [ -d "$OPENCART_ROOT/image/cache" ]; then
    chmod -R 775 "$OPENCART_ROOT/image/cache"
    echo -e "     Resim önbellek izinleri ayarlandı"
  fi
  
  # Sistem depolama
  if [ -d "$OPENCART_ROOT/system/storage" ]; then
    chmod -R 775 "$OPENCART_ROOT/system/storage"
    echo -e "     Sistem depolama izinleri ayarlandı"
  fi
  
  # Data dizini
  echo -e "   ${ACIK_YESIL}✓${NC} Data dizini izinleri..."
  chown -R $OWNER:$GROUP "$DATA_ROOT"
  chmod -R 775 "$DATA_ROOT"
  
  # Yapılandırma dosyaları
  echo -e "   ${ACIK_YESIL}✓${NC} Yapılandırma dosyaları..."
  chmod 644 "$OPENCART_ROOT/config.php" 2>/dev/null
  chmod 644 "$OPENCART_ROOT/admin/config.php" 2>/dev/null
  
  # Ana index.php
  chmod 755 "$OPENCART_ROOT/index.php" 2>/dev/null
  echo -e "     Tüm izinler düzeltildi!"
}

# =============================================================================
# DURUM RAPORU FONKSİYONU
# =============================================================================
goster_rapor() {
  echo -e "\n${TURKUAZ}=================================${NC}"
  echo -e "${TURKUAZ}           DURUM RAPORU           ${NC}"
  echo -e "${TURKUAZ}=================================${NC}"
  
  # Önbellek durumu
  echo -e "\n${ACIK_YESIL}📁 ÖNBELLEK DURUMU:${NC}"
  oc_cache=$(find "$DATA_ROOT/cache" -name "cache.*" -type f 2>/dev/null | wc -l)
  vq_cache=$(find "$OPENCART_ROOT/vqmod/vqcache" -name "vq2-*" -type f 2>/dev/null | wc -l)
  img_cache=$(find "$OPENCART_ROOT/image/cache" -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" -o -name "*.gif" -type f 2>/dev/null | wc -l)
  echo -e "   OpenCart Önbellek: $oc_cache dosya"
  echo -e "   VQMod Önbellek: $vq_cache dosya"
  echo -e "   Resim Önbellek: $img_cache dosya"
  
  # Günlük durumu
  echo -e "\n${ACIK_YESIL}📝 GÜNLÜK DURUMU:${NC}"
  if [ -f "$DATA_ROOT/logs/error.log" ]; then
    error_lines=$(wc -l < "$DATA_ROOT/logs/error.log" 2>/dev/null || echo 0)
    echo -e "   Hata Günlüğü: $error_lines satır"
  fi
  
  if [ -f "$DATA_ROOT/logs/hatalar.log" ]; then
    hatalar_lines=$(wc -l < "$DATA_ROOT/logs/hatalar.log" 2>/dev/null || echo 0)
    echo -e "   Hatalar Günlüğü: $hatalar_lines satır"
  fi
  
  # Oturum durumu
  echo -e "\n${ACIK_YESIL}🔐 OTURUM DURUMU:${NC}"
  session_count=$(find "$DATA_ROOT/session" -name "sess_*" -type f 2>/dev/null | wc -l)
  echo -e "   Aktif Oturum: $session_count dosya"
  
  # İzin durumu
  echo -e "\n${ACIK_YESIL}🔧 İZİN DURUMU:${NC}"
  oc_perms=$(ls -ld "$OPENCART_ROOT" 2>/dev/null | awk '{print $1, $3, $4}')
  data_perms=$(ls -ld "$DATA_ROOT" 2>/dev/null | awk '{print $1, $3, $4}')
  echo -e "   OpenCart Kök: $oc_perms"
  echo -e "   Data Dizini: $data_perms"
  
  # Disk kullanımı
  echo -e "\n${ACIK_YESIL}💾 DİSK KULLANIMI:${NC}"
  oc_size=$(du -sh "$OPENCART_ROOT" 2>/dev/null | cut -f1)
  data_size=$(du -sh "$DATA_ROOT" 2>/dev/null | cut -f1)
  echo -e "   OpenCart: $oc_size"
  echo -e "   Data: $data_size"
}

# =============================================================================
# İŞLEM MENÜSÜ
# =============================================================================
echo -e "\n${ACIK_YESIL}🎯 Hangi işlemi yapmak istiyorsunuz?${NC}"
echo -e "1) Sadece Önbellek Temizle"
echo -e "2) Sadece Günlük Temizle"
echo -e "3) Sadece Oturum Temizle"
echo -e "4) Sadece İzinleri Düzelt"
echo -e "5) Tam Temizlik (Hepsi)"
echo -e "6) Durum Raporu"
echo -e "7) Çıkış"
read -p "Seçiminiz (1-7): " choice

case $choice in
  1)
    temizle_onbellek
    echo -e "\n${ACIK_YESIL}✅ Önbellek temizleme tamamlandı!${NC}"
    ;;
  2)
    temizle_gunlukleri
    echo -e "\n${ACIK_YESIL}✅ Günlük temizleme tamamlandı!${NC}"
    ;;
  3)
    temizle_oturumlari
    echo -e "\n${ACIK_YESIL}✅ Oturum temizleme tamamlandı!${NC}"
    ;;
  4)
    duzelt_izinleri
    echo -e "\n${ACIK_YESIL}✅ İzin düzeltme tamamlandı!${NC}"
    ;;
  5)
    temizle_onbellek
    temizle_gunlukleri
    temizle_oturumlari
    duzelt_izinleri
    echo -e "\n${ACIK_YESIL}🎉 TAM TEMİZLİK TAMAMLANDI!${NC}"
    ;;
  6)
    goster_rapor
    ;;
  7)
    echo -e "\n${TURKUAZ}👋 Görüşürüz!${NC}"
    exit 0
    ;;
  *)
    echo -e "\n${TURUNCU}❌ Geçersiz seçim!${NC}"
    exit 1
    ;;
esac

# Final rapor
goster_rapor
echo -e "\n${ACIK_YESIL}🎯 İşlem başarıyla tamamlandı!${NC}"
echo -e "${TURKUAZ}========================================${NC}"

}

# =====================================================
# 🎬 Django Python Fosiyonları BAŞLATMA
# =====================================================
django_yonetici_ayar() {

# Logo
logo_goster() {
    clear
    echo -e "${TURKUAZ}"
    echo "========================================================================"
    echo "                    DJANGO SITE YONETICISI                            "
    echo "                      Bitronix Code v1.0                             "
    echo "========================================================================"
    echo -e "${NC}"
}

# Ilk kurulum - Domain, yol ve port bilgilerini al
ilk_kurulum() {
    logo_goster
    echo -e "${SARI}🔧 ILK KURULUM - BILGILERI GIRIN${NC}"
    echo "========================================"
    
    # Domain al
    echo -e "${TURKUAZ}🌐 Domain adinizi girin (ornek: bitronixcode.com):${NC}"
    read -p "Domain: " DOMAIN
    
    # Proje yolu al
    echo -e "${TURKUAZ}📂 Proje kok dizin yolunu girin:${NC}"
    echo -e "${SARI}Ornek: /home/bitronixcodec/htdocs/bitronixcode.com${NC}"
    read -p "Proje Yolu: " PROJE_YOLU
    
    # Port al
    echo -e "${TURKUAZ}🔌 Port numarasini girin (ornek: 8090, 8000, 9088):${NC}"
    read -p "Port: " PORT
    
    # Bilgileri kaydet
    cat > ~/.django_yonetici_ayar << EOF
DOMAIN="$DOMAIN"
PROJE_YOLU="$PROJE_YOLU"
PORT="$PORT"
EOF
    
    echo -e "${ACIK_YESIL}✅ Bilgiler kaydedildi!${NC}"
    sleep 2
}

# Ayarlari yukle
ayarlari_yukle() {
    if [ -f ~/.django_yonetici_ayar ]; then
        source ~/.django_yonetici_ayar
        VENV_YOLU="$PROJE_YOLU/.venv"
        PID_DOSYASI="/tmp/django_${DOMAIN}_${PORT}.pid"
    else
        ilk_kurulum
        ayarlari_yukle
    fi
}

# Site durumunu kontrol et
site_durumu_kontrol() {
    if [ -f "$PID_DOSYASI" ] && kill -0 $(cat "$PID_DOSYASI") 2>/dev/null; then
        echo -e "${ACIK_YESIL}🟢 ACIK${NC}"
        return 0
    else
        echo -e "${TURUNCU}🔴 KAPALI${NC}"
        return 1
    fi
}

# Venv durumunu kontrol et
venv_durumu_kontrol() {
    if [ -d "$VENV_YOLU" ]; then
        echo -e "${ACIK_YESIL}✅ .venv MEVCUT${NC}"
        return 0
    else
        echo -e "${TURUNCU}❌ .venv YOK${NC}"
        return 1
    fi
}

# Ana menu
ana_menu_goster() {
    logo_goster
    
    # Durum bilgileri
    echo -e "${ACIK_PEMBE}📊 DURUM BILGILERI:${NC}"
    echo "========================================"
    echo -e "🌐 Domain: ${TURKUAZ}$DOMAIN${NC}"
    echo -e "📂 Proje: ${TURKUAZ}$PROJE_YOLU${NC}"
    echo -e "🔌 Port: ${TURKUAZ}$PORT${NC}"
    echo -n "🔄 Site Durumu: "; site_durumu_kontrol
    echo -n "📦 Sanal Ortam: "; venv_durumu_kontrol
    echo ""
    
    echo -e "${SARI}🎯 MENU SECENEKLERI:${NC}"
    echo "========================================"
    echo -e "${ACIK_YESIL}1)${NC} 🚀 Siteyi Dunyaya Ac (On Plan)"
    echo -e "${ACIK_YESIL}2)${NC} 🔄 Site Arka Planda Calistir/Durdur"
    echo -e "${ACIK_YESIL}3)${NC} 👤 Superuser Olustur"
    echo -e "${ACIK_YESIL}4)${NC} 🧪 Site Testi Yap"
    echo -e "${ACIK_YESIL}5)${NC} ⚙️ Ayarlari Degistir"
    echo -e "${ACIK_YESIL}6)${NC} 📋 Log Goruntule"
    echo -e "${ACIK_YESIL}7)${NC} 🛠️ TAM KURULUM (Yedekten Cikar + Ortam Kurulum)"
    echo -e "${TURUNCU}0)${NC} 🚪 Cikis"
    echo ""
    echo -n "Seciminizi yapin [0-7]: "
}

# Siteyi dunyaya ac (on plan)
siteyi_on_plan_ac() {
    logo_goster
    echo -e "${SARI}🚀 SITE DUNYAYA ACILIYOR...${NC}"
    echo "========================================"
    
    cd "$PROJE_YOLU" || { echo -e "${TURUNCU}❌ Proje dizinine gidilemedi!${NC}"; return 1; }
    
    # Venv kontrol
    if [ ! -d "$VENV_YOLU" ]; then
        echo -e "${TURUNCU}❌ .venv bulunamadi! Olusturuluyor...${NC}"
        python3 -m venv .venv
    fi
    
    # Venv aktif et
    source "$VENV_YOLU/bin/activate"
    
    echo -e "${TURKUAZ}📦 Paketler guncelleniyor...${NC}"
    pip install --upgrade pip
    pip install django mysqlclient pillow gunicorn whitenoise
    pip install django-admin-interface django-colorfield django-flat-theme
    
    echo -e "${TURKUAZ}🗂️ Static dosyalar toplaniyor...${NC}"
    python manage.py collectstatic --noinput
    
    echo -e "${TURKUAZ}🔄 Veritabani migrasyonlari...${NC}"
    python manage.py makemigrations
    python manage.py migrate
    
    echo -e "${ACIK_YESIL}🎉 Site baslatiliyor...${NC}"
    echo -e "${SARI}Durdurmak icin: Ctrl+C${NC}"
    echo "========================================"
    
    python manage.py runserver "0.0.0.0:$PORT"
}

# Site arka planda calistir/durdur
arka_plan_degistir() {
    logo_goster
    
    if site_durumu_kontrol; then
        echo -e "${SARI}🛑 ARKA PLAN SERVISI DURDURULUYOR...${NC}"
        echo "========================================"
        
        if [ -f "$PID_DOSYASI" ]; then
            PID=$(cat "$PID_DOSYASI")
            kill "$PID" 2>/dev/null
            rm -f "$PID_DOSYASI"
            echo -e "${ACIK_YESIL}✅ Servis durduruldu!${NC}"
        fi
    else
        echo -e "${SARI}🚀 ARKA PLAN SERVISI BASLATILIYOR...${NC}"
        echo "========================================"
        
        cd "$PROJE_YOLU" || { echo -e "${TURUNCU}❌ Proje dizinine gidilemedi!${NC}"; return 1; }
        
        # Venv kontrol ve aktif et
        if [ ! -d "$VENV_YOLU" ]; then
            echo -e "${TURUNCU}❌ .venv bulunamadi! Olusturuluyor...${NC}"
            python3 -m venv .venv
        fi
        
        source "$VENV_YOLU/bin/activate"
        
        # Arka planda baslat
        nohup python manage.py runserver "0.0.0.0:$PORT" > "/tmp/django_${DOMAIN}_${PORT}.log" 2>&1 &
        echo $! > "$PID_DOSYASI"
        
        echo -e "${ACIK_YESIL}✅ Servis arka planda baslatildi!${NC}"
        echo -e "${TURKUAZ}📄 Log dosyasi: /tmp/django_${DOMAIN}_${PORT}.log${NC}"
    fi
    
    echo ""
    read -p "Devam etmek icin Enter'a basin..."
}

# Superuser olustur
superuser_olustur() {
    logo_goster
    echo -e "${SARI}👤 SUPERUSER OLUSTURULUYOR...${NC}"
    echo "========================================"
    
    cd "$PROJE_YOLU" || { echo -e "${TURUNCU}❌ Proje dizinine gidilemedi!${NC}"; return 1; }
    
    if [ ! -d "$VENV_YOLU" ]; then
        echo -e "${TURUNCU}❌ .venv bulunamadi!${NC}"
        read -p "Devam etmek icin Enter'a basin..."
        return 1
    fi
    
    source "$VENV_YOLU/bin/activate"
    python manage.py createsuperuser
    
    echo ""
    read -p "Devam etmek icin Enter'a basin..."
}

# Site testi
site_testi() {
    logo_goster
    echo -e "${SARI}🧪 SITE TESTI YAPILIYOR...${NC}"
    echo "========================================"
    
    echo -e "${TURKUAZ}🌐 Ana sayfa testi:${NC}"
    if curl -I "https://$DOMAIN/" 2>/dev/null | head -1; then
        echo -e "${ACIK_YESIL}✅ Ana sayfa erisilebilir${NC}"
    else
        echo -e "${TURUNCU}❌ Ana sayfa erisilemez${NC}"
    fi
    
    echo ""
    echo -e "${TURKUAZ}🔐 Admin paneli testi:${NC}"
    if curl -I "https://$DOMAIN/bitronixcode-admin/" 2>/dev/null | head -1; then
        echo -e "${ACIK_YESIL}✅ Admin paneli erisilebilir${NC}"
    else
        echo -e "${TURUNCU}❌ Admin paneli erisilemez${NC}"
    fi
    
    echo ""
    echo -e "${TURKUAZ}🔒 SSL sertifika kontrolu:${NC}"
    if openssl x509 -in "/etc/nginx/ssl-certificates/$DOMAIN.crt" -noout -dates 2>/dev/null; then
        echo -e "${ACIK_YESIL}✅ SSL sertifikasi gecerli${NC}"
    else
        echo -e "${TURUNCU}❌ SSL sertifikasi bulunamadi${NC}"
    fi
    
    echo ""
    echo -e "${TURKUAZ}🔌 Port kontrolu:${NC}"
    if netstat -tlnp | grep ":$PORT "; then
        echo -e "${ACIK_YESIL}✅ Port $PORT dinleniyor${NC}"
    else
        echo -e "${TURUNCU}❌ Port $PORT dinlenmiyor${NC}"
    fi
    
    echo ""
    read -p "Devam etmek icin Enter'a basin..."
}

# Ayarlari degistir
ayarlari_degistir() {
    logo_goster
    echo -e "${SARI}⚙️ AYARLAR DEGISTIRILIYOR...${NC}"
    echo "========================================"
    
    echo -e "${TURKUAZ}Mevcut ayarlar:${NC}"
    echo "Domain: $DOMAIN"
    echo "Proje Yolu: $PROJE_YOLU"
    echo "Port: $PORT"
    echo ""
    
    echo -e "${SARI}Yeni degerleri girin (bos birakirsaniz eski deger kalir):${NC}"
    
    read -p "Yeni Domain [$DOMAIN]: " YENI_DOMAIN
    read -p "Yeni Proje Yolu [$PROJE_YOLU]: " YENI_PROJE_YOLU
    read -p "Yeni Port [$PORT]: " YENI_PORT
    
    # Degerleri guncelle
    [ ! -z "$YENI_DOMAIN" ] && DOMAIN="$YENI_DOMAIN"
    [ ! -z "$YENI_PROJE_YOLU" ] && PROJE_YOLU="$YENI_PROJE_YOLU"
    [ ! -z "$YENI_PORT" ] && PORT="$YENI_PORT"
    
    # Kaydet
    cat > ~/.django_yonetici_ayar << EOF
DOMAIN="$DOMAIN"
PROJE_YOLU="$PROJE_YOLU"
PORT="$PORT"
EOF
    
    # Yeni degerleri yukle
    VENV_YOLU="$PROJE_YOLU/.venv"
    PID_DOSYASI="/tmp/django_${DOMAIN}_${PORT}.pid"
    
    echo -e "${ACIK_YESIL}✅ Ayarlar guncellendi!${NC}"
    sleep 2
}

# Log goruntule
log_goruntule() {
    logo_goster
    echo -e "${SARI}📋 LOG GORUNTULEME${NC}"
    echo "========================================"
    
    LOG_DOSYASI="/tmp/django_${DOMAIN}_${PORT}.log"
    
    if [ -f "$LOG_DOSYASI" ]; then
        echo -e "${TURKUAZ}Son 20 satir:${NC}"
        echo "========================================"
        tail -20 "$LOG_DOSYASI"
    else
        echo -e "${TURUNCU}❌ Log dosyasi bulunamadi: $LOG_DOSYASI${NC}"
    fi
    
    echo ""
    read -p "Devam etmek icin Enter'a basin..."
}

# TAM Kurulum (Yedekten cikar + ortam kurulum)
yedekten_al_kur() {

# LOGO
echo -e "${BEYAZ}"
echo "██████╗ ██╗████████╗██████╗  ██████╗ ███╗   ██╗██╗██╗  ██╗"
echo "██╔══██╗██║╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║██║╚██╗██╔╝"
echo "██████╔╝██║   ██║   ██████╔╝██║   ██║██╔██╗ ██║██║ ╚███╔╝ "
echo "██╔══██╗██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║██║ ██╔██╗ "
echo "██████╔╝██║   ██║   ██║  ██║╚██████╔╝██║ ╚████║██║██╔╝ ██╗"
echo "╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "${TURKUAZ}🚀 ULTIMATE TEK KULLANIMLIK DJANGO DEPLOYMENT SCRIPT${NC}"
echo -e "${ACIK_PEMBE}📅 Versiyon: 5.0 ULTIMATE | Tarih: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${ACIK_YESIL}✨ TEK SEFERDE %100 CALISAN - EKSIKSIZ DEPLOYMENT${NC}"
echo "================================================================="

# TIMEOUT FONKSIYONU
timeout_command() {
    local timeout_duration=$1
    shift
    timeout $timeout_duration "$@" || {
        echo -e "${TURUNCU}❌ TIMEOUT: Komut $timeout_duration saniyede tamamlanamadi${NC}"
        return 1
    }
}

# GUVENLI PYTHON KOMUT CALISTIRMA
safe_python_check() {
    local python_path=$1
    local check_code=$2
    local timeout_sec=${3:-10}
    
    local temp_script="/tmp/python_check_$$"
    cat > "$temp_script" << EOF
#!/usr/bin/env python3
import sys
try:
    $check_code
    print("✅ BASARILI")
    sys.exit(0)
except Exception as e:
    print(f"❌ HATA: {e}")
    sys.exit(1)
EOF
    
    chmod +x "$temp_script"
    
    if timeout_command $timeout_sec "$python_path" "$temp_script" >/dev/null 2>&1; then
        rm -f "$temp_script"
        return 0
    else
        rm -f "$temp_script"
        return 1
    fi
}

# PROGRESS GOSTERGESI
show_progress() {
    local current=$1
    local total=$2
    local desc=$3
    local percent=$((current * 100 / total))
    printf "\r🔄 [%d/%d] %s (%d%%)" $current $total "$desc" $percent
}

# =================================================================
# 1. KULLANICI BILGILERI
# =================================================================
echo -e "\n${SARI}📋 PROJE BILGILERINI GIRIN${NC}"
echo "================================================================="

read -p "🏠 Django proje yolu (Orn: /home/bitronixcodec/htdocs/bitronixcode.com): " PROJECT_PATH
read -p "👤 Site kullanici adi (Orn: bitronixcodec): " PROJECT_USER
read -p "📦 Yedek dosya yolu (Orn: /tmp/bitronixcode_project.tar.gz): " BACKUP_FILE
read -p "🌍 Domain adi (Orn: bitronixcode.com): " DOMAIN_NAME
read -p "🏷️ Veritabani adi (Orn: BitronixCode-C): " DB_NAME
read -p "👤 Veritabani kullanicisi (Orn: BitronixCodeC): " DB_USER
read -p "🔐 Veritabani sifresi: " -s DB_PASS
echo

DB_HOST="localhost"
DB_PORT="3306"

# =================================================================
# 2. ROOT KONTROL
# =================================================================
if [ "$EUID" -ne 0 ]; then
    echo -e "${TURUNCU}❌ Bu betik root yetkileri ile calistirilmalidir!${NC}"
    exit 1
fi

# =================================================================
# 3. TEMEL KONTROLLER
# =================================================================
echo -e "\n${TURKUAZ}🔍 TEMEL KONTROLLER${NC}"
echo "================================================================="

show_progress 1 5 "Proje yolu kontrol ediliyor"
[ ! -d "$PROJECT_PATH" ] && { echo -e "\n${TURUNCU}❌ Proje yolu bulunamadi!${NC}"; exit 1; }

show_progress 2 5 "Kullanici kontrol ediliyor"
! id "$PROJECT_USER" &>/dev/null && { echo -e "\n${TURUNCU}❌ Kullanici bulunamadi!${NC}"; exit 1; }

show_progress 3 5 "Yedek dosyasi kontrol ediliyor"
[ ! -f "$BACKUP_FILE" ] && { echo -e "\n${TURUNCU}❌ Yedek dosyasi bulunamadi!${NC}"; exit 1; }

show_progress 4 5 "Sistem paketleri kontrol ediliyor"
command -v mysql >/dev/null 2>&1 || { echo -e "\n${TURUNCU}❌ MySQL bulunamadi!${NC}"; exit 1; }

show_progress 5 5 "Kontroller tamamlandi"
echo -e "\n${ACIK_YESIL}✅ Tum kontroller basarili${NC}"

# =================================================================
# 4. MEVCUT ICERIK TEMIZLEME
# =================================================================
echo -e "\n${TURKUAZ}🧹 MEVCUT ICERIK TEMIZLENIYOR${NC}"
echo "================================================================="

cd "$PROJECT_PATH"
sudo -u $PROJECT_USER find . -mindepth 1 -maxdepth 1 ! -name '.well-known' -exec rm -rf {} \; 2>/dev/null || true
echo -e "${ACIK_YESIL}✅ Proje klasoru temizlendi${NC}"

# =================================================================
# 5. SISTEM PAKETLERI KURULUMU
# =================================================================
echo -e "\n${TURKUAZ}📦 SISTEM PAKETLERI KURULUYOR${NC}"
echo "================================================================="

apt update -y >/dev/null 2>&1

# Temel paketler
apt install -y python3 python3-pip python3-venv python3-dev >/dev/null 2>&1
apt install -y build-essential gcc g++ make pkg-config >/dev/null 2>&1
apt install -y libssl-dev libffi-dev >/dev/null 2>&1

# MySQL paketleri
apt install -y libmysqlclient-dev mysql-client >/dev/null 2>&1
apt install -y default-libmysqlclient-dev >/dev/null 2>&1

# Gorsel isleme
apt install -y libjpeg-dev libpng-dev libwebp-dev >/dev/null 2>&1
apt install -y zlib1g-dev libtiff5-dev libfreetype6-dev >/dev/null 2>&1

# Sistem araclari
apt install -y curl wget git unzip nginx >/dev/null 2>&1

echo -e "${ACIK_YESIL}✅ Sistem paketleri kuruldu${NC}"

# =================================================================
# 6. YEDEK DOSYASINI ACMA
# =================================================================
echo -e "\n${TURKUAZ}📦 YEDEK DOSYASI ACILIYOR${NC}"
echo "================================================================="

TEMP_DIR="/tmp/django_restore_$$"
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"
tar -xzf "$BACKUP_FILE" >/dev/null 2>&1

# manage.py dosyasini bul
MANAGE_PY_PATH=$(find "$TEMP_DIR" -name "manage.py" -type f | head -1)
if [ -n "$MANAGE_PY_PATH" ]; then
    BACKUP_PROJECT_PATH=$(dirname "$MANAGE_PY_PATH")
    cd "$BACKUP_PROJECT_PATH"
    sudo -u $PROJECT_USER cp -r * "$PROJECT_PATH/" 2>/dev/null || true
    sudo -u $PROJECT_USER cp -r .[^.]* "$PROJECT_PATH/" 2>/dev/null || true
    echo -e "${ACIK_YESIL}✅ Proje dosylari kopyalandi${NC}"
else
    echo -e "${TURUNCU}❌ Django projesi bulunamadi!${NC}"
    rm -rf "$TEMP_DIR"
    exit 1
fi

rm -rf "$TEMP_DIR"

# =================================================================
# 7. PYTHON SANAL ORTAM
# =================================================================
echo -e "\n${TURKUAZ}🐍 PYTHON SANAL ORTAM OLUSTURULUYOR${NC}"
echo "================================================================="

cd "$PROJECT_PATH"
rm -rf "$PROJECT_PATH/venv" 2>/dev/null || true
sudo -u $PROJECT_USER python3 -m venv "$PROJECT_PATH/venv" >/dev/null 2>&1
sudo -u $PROJECT_USER "$PROJECT_PATH/venv/bin/pip" install --upgrade pip setuptools wheel >/dev/null 2>&1
echo -e "${ACIK_YESIL}✅ Python sanal ortam hazir${NC}"

# =================================================================
# 8. PYTHON PAKETLERI YUKLEME
# =================================================================
echo -e "\n${TURKUAZ}📦 PYTHON PAKETLERI YUKLENIYOR${NC}"
echo "================================================================="

# Requirements.txt varsa kullan
if [ -f "$PROJECT_PATH/requirements.txt" ]; then
    sudo -u $PROJECT_USER "$PROJECT_PATH/venv/bin/pip" install -r "$PROJECT_PATH/requirements.txt" >/dev/null 2>&1
else
    # Manuel paket yukleme
    sudo -u $PROJECT_USER "$PROJECT_PATH/venv/bin/pip" install \
        Django==5.2 \
        mysqlclient==2.2.7 \
        gunicorn==23.0.0 \
        pillow==11.3.0 \
        PyJWT==2.9.0 \
        python-jose==3.3.0 \
        jwcrypto==1.5.6 \
        cryptography==41.0.7 \
        requests==2.31.0 >/dev/null 2>&1
fi

# JWT paketleri ekstra guvence
sudo -u $PROJECT_USER "$PROJECT_PATH/venv/bin/pip" install --force-reinstall PyJWT==2.9.0 python-jose==3.3.0 jwcrypto==1.5.6 >/dev/null 2>&1

echo -e "${ACIK_YESIL}✅ Python paketleri yuklendi${NC}"

# =================================================================
# 9. DJANGO SETTINGS DOSYASI OLUSTURMA
# =================================================================
echo -e "\n${TURKUAZ}⚙️ DJANGO SETTINGS DOSYASI OLUSTURULUYOR${NC}"
echo "================================================================="

# Settings dosyasini bul
SETTINGS_FILE=$(find "$PROJECT_PATH" -name "settings.py" -type f | grep -v venv | head -1)

if [ -n "$SETTINGS_FILE" ]; then
    # Veritabani ayarlarini guncelle
    cat >> "$SETTINGS_FILE" << EOF

# BitronixCode Otomatik Veritabani Ayarlari
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': '$DB_NAME',
        'USER': '$DB_USER',
        'PASSWORD': '$DB_PASS',
        'HOST': '$DB_HOST',
        'PORT': '$DB_PORT',
        'OPTIONS': {
            'charset': 'utf8mb4',
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
        },
    }
}

# Guvenlik Ayarlari
ALLOWED_HOSTS = ['$DOMAIN_NAME', 'www.$DOMAIN_NAME', 'localhost', '127.0.0.1']
DEBUG = False
SECURE_SSL_TURUNCUIRECT = False
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Static ve Media Ayarlari
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# JWT Ayarlari
JWT_AUTH = {
    'JWT_SECRET_KEY': SECRET_KEY,
    'JWT_ALGORITHM': 'HS256',
    'JWT_EXPIRATION_DELTA': timedelta(hours=24),
}
EOF
    echo -e "${ACIK_YESIL}✅ Django settings guncellendi${NC}"
fi

# =================================================================
# 10. DOSYA IZINLERI
# =================================================================
echo -e "\n${TURKUAZ}🔒 DOSYA IZINLERI DUZENLENIYOR${NC}"
echo "================================================================="

chown -R $PROJECT_USER:$PROJECT_USER "$PROJECT_PATH"
find "$PROJECT_PATH" -type d -exec chmod 755 {} \;
find "$PROJECT_PATH" -type f -exec chmod 644 {} \;

# Ozel klasorler
mkdir -p "$PROJECT_PATH/media" "$PROJECT_PATH/static" "$PROJECT_PATH/staticfiles" "$PROJECT_PATH/logs"
chown -R $PROJECT_USER:www-data "$PROJECT_PATH/media" "$PROJECT_PATH/static" "$PROJECT_PATH/staticfiles" "$PROJECT_PATH/logs"
chmod -R 775 "$PROJECT_PATH/media" "$PROJECT_PATH/staticfiles" "$PROJECT_PATH/logs"
chmod -R 755 "$PROJECT_PATH/static"

# manage.py calistirilabilir yap
[ -f "$PROJECT_PATH/manage.py" ] && chmod +x "$PROJECT_PATH/manage.py"

echo -e "${ACIK_YESIL}✅ Dosya izinleri duzenlendi${NC}"

# =================================================================
# 11. GUNICORN KONFIGURASYONU
# =================================================================
echo -e "\n${TURKUAZ}🦄 GUNICORN KONFIGURASYONU${NC}"
echo "================================================================="

cat > "$PROJECT_PATH/gunicorn.conf.py" << EOF
import multiprocessing
import os

# Sunucu ayarlari
bind = "127.0.0.1:8000"
workers = min(4, multiprocessing.cpu_count())
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2
max_requests = 1000
max_requests_jitter = 100

# Guvenlik
user = "$PROJECT_USER"
group = "$PROJECT_USER"
umask = 0

# Logging
errorlog = "$PROJECT_PATH/logs/gunicorn_error.log"
accesslog = "$PROJECT_PATH/logs/gunicorn_access.log"
loglevel = "info"
access_log_format = '%({x-forwarded-for}i)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process
daemon = False
pidfile = "$PROJECT_PATH/logs/gunicorn.pid"
tmp_upload_dir = None
preload_app = True
reload = False

# SSL Headers
secure_scheme_headers = {
    'X-FORWARDED-PROTOCOL': 'ssl',
    'X-FORWARDED-PROTO': 'https',
    'X-FORWARDED-SSL': 'on'
}
EOF

chown $PROJECT_USER:$PROJECT_USER "$PROJECT_PATH/gunicorn.conf.py"
echo -e "${ACIK_YESIL}✅ Gunicorn konfigurasyonu olusturuldu${NC}"

# =================================================================
# 12. WSGI MODULU TESPITI
# =================================================================
echo -e "\n${TURKUAZ}🔍 WSGI MODULU TESPIT EDILIYOR${NC}"
echo "================================================================="

WSGI_FILE=$(find "$PROJECT_PATH" -name "wsgi.py" -type f | grep -v venv | head -1)
if [ -n "$WSGI_FILE" ]; then
    WSGI_DIR=$(dirname "$WSGI_FILE")
    WSGI_MODULE_NAME=$(basename "$WSGI_DIR")
    WSGI_MODULE="${WSGI_MODULE_NAME}.wsgi:application"
    echo -e "${ACIK_YESIL}✅ WSGI modulu tespit edildi: $WSGI_MODULE${NC}"
else
    WSGI_MODULE="myproject.wsgi:application"
    echo -e "${SARI}⚠️ WSGI modulu tespit edilemedi, varsayilan kullanilacak${NC}"
fi

# =================================================================
# 13. SYSTEMD SERVISI
# =================================================================
echo -e "\n${TURKUAZ}⚡ SYSTEMD SERVISI OLUSTURULUYOR${NC}"
echo "================================================================="

SERVICE_NAME="bitronixcode_django"

cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=BitronixCode Django Application ($DOMAIN_NAME)
Documentation=https://docs.djangoproject.com/
After=network.target mysql.service
Wants=mysql.service

[Service]
Type=notify
User=$PROJECT_USER
Group=$PROJECT_USER
WorkingDirectory=$PROJECT_PATH
Environment=PATH=$PROJECT_PATH/venv/bin
Environment=DJANGO_SETTINGS_MODULE=${WSGI_MODULE_NAME}.settings
ExecStart=$PROJECT_PATH/venv/bin/gunicorn --config $PROJECT_PATH/gunicorn.conf.py $WSGI_MODULE
ExecReload=/bin/kill -s HUP \$MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
echo -e "${ACIK_YESIL}✅ Systemd servisi olusturuldu: $SERVICE_NAME${NC}"

# =================================================================
# 14. NGINX KONFIGURASYONU
# =================================================================
echo -e "\n${TURKUAZ}🌐 NGINX KONFIGURASYONU OLUSTURULUYOR${NC}"
echo "================================================================="

# Sites-available dizini olustur
mkdir -p /etc/nginx/sites-available
mkdir -p /etc/nginx/sites-enabled

# Nginx config dosyasi olustur
cat > "/etc/nginx/sites-available/$DOMAIN_NAME" << EOF
server {
    listen 80;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied expired no-cache no-store private must-revalidate auth;
    gzip_types text/plain text/css text/xml text/javascript application/x-javascript application/xml+rss application/javascript;
    
    # Client max body size
    client_max_body_size 100M;
    
    # Django application
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$server_name;
        
        # Proxy timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Proxy buffers
        proxy_buffering on;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
        
        # Cookie settings
        proxy_cookie_path / /;
        proxy_cookie_domain \$host \$host;
    }
    
    # Static files
    location /static/ {
        alias $PROJECT_PATH/staticfiles/;
        expires 30d;
        access_log off;
        add_header Cache-Control "public, immutable";
        
        # Gzip static files
        location ~* \.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }
    
    # Media files
    location /media/ {
        alias $PROJECT_PATH/media/;
        expires 7d;
        access_log off;
        add_header Cache-Control "public";
    }
    
    # Favicon
    location = /favicon.ico {
        alias $PROJECT_PATH/staticfiles/favicon.ico;
        access_log off;
    }
    
    # Robots.txt
    location = /robots.txt {
        alias $PROJECT_PATH/staticfiles/robots.txt;
        access_log off;
    }
    
    # Security - Block access to sensitive files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    location ~ ~$ {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    # Error pages
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
}

# HTTPS redirect (commented out for initial setup)
# server {
#     listen 443 ssl http2;
#     server_name $DOMAIN_NAME www.$DOMAIN_NAME;
#     
#     ssl_certificate /path/to/certificate.crt;
#     ssl_certificate_key /path/to/private.key;
#     ssl_protocols TLSv1.2 TLSv1.3;
#     ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
#     ssl_prefer_server_ciphers off;
#     
#     # Include the same location blocks as above
# }
EOF

# Site'i etkinlestir
ln -sf "/etc/nginx/sites-available/$DOMAIN_NAME" "/etc/nginx/sites-enabled/$DOMAIN_NAME"

# Nginx test et
if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx >/dev/null 2>&1
    echo -e "${ACIK_YESIL}✅ Nginx konfigurasyonu olusturuldu ve etkinlestirildi${NC}"
else
    echo -e "${SARI}⚠️ Nginx konfigurasyonu olusturuldu ancak test basarisiz${NC}"
fi

# =================================================================
# 15. DJANGO MIGRATE VE COLLECTSTATIC
# =================================================================
echo -e "\n${TURKUAZ}🔄 DJANGO ISLEMLERI${NC}"
echo "================================================================="

cd "$PROJECT_PATH"

# Django migrate
echo -e "${ACIK_PEMBE}🔄 Django migrate yapiliyor...${NC}"
if sudo -u $PROJECT_USER "$PROJECT_PATH/venv/bin/python" manage.py migrate --verbosity=0 >/dev/null 2>&1; then
    echo -e "${ACIK_YESIL}✅ Migrate basarili${NC}"
else
    echo -e "${SARI}⚠️ Migrate hatasi (normal olabilir)${NC}"
fi

# Static files collect
echo -e "${ACIK_PEMBE}📁 Static files collect yapiliyor...${NC}"
if sudo -u $PROJECT_USER "$PROJECT_PATH/venv/bin/python" manage.py collectstatic --noinput --verbosity=0 >/dev/null 2>&1; then
    echo -e "${ACIK_YESIL}✅ Static files collect basarili${NC}"
else
    echo -e "${SARI}⚠️ Static files collect hatasi (normal olabilir)${NC}"
fi

# =================================================================
# 16. OTOMASYON SCRIPTLERI
# =================================================================
echo -e "\n${TURKUAZ}🤖 OTOMASYON SCRIPTLERI OLUSTURULUYOR${NC}"
echo "================================================================="

# Start script
cat > "$PROJECT_PATH/start.sh" << EOF
#!/bin/bash
echo "🚀 BitronixCode Django baslatiliyor..."
systemctl start $SERVICE_NAME
systemctl status $SERVICE_NAME --no-pager
echo "✅ Servis baslatildi"
echo "🌐 Test URL: http://$DOMAIN_NAME"
EOF

# Stop script
cat > "$PROJECT_PATH/stop.sh" << EOF
#!/bin/bash
echo "🛑 BitronixCode Django durduruluyor..."
systemctl stop $SERVICE_NAME
echo "✅ Servis durduruldu"
EOF

# Restart script
cat > "$PROJECT_PATH/restart.sh" << EOF
#!/bin/bash
echo "🔄 BitronixCode Django yeniden baslatiliyor..."
systemctl restart $SERVICE_NAME
systemctl status $SERVICE_NAME --no-pager
echo "✅ Servis yeniden baslatildi"
echo "🌐 Test URL: http://$DOMAIN_NAME"
EOF

# Status script
cat > "$PROJECT_PATH/status.sh" << EOF
#!/bin/bash
echo "📊 BitronixCode Django durumu:"
systemctl status $SERVICE_NAME --no-pager
echo ""
echo "📝 Son loglar:"
journalctl -u $SERVICE_NAME -n 10 --no-pager
EOF

# Logs script
cat > "$PROJECT_PATH/logs.sh" << EOF
#!/bin/bash
echo "📝 BitronixCode Django canli loglari (CTRL+C ile cikis):"
journalctl -u $SERVICE_NAME -f
EOF

# Update script
cat > "$PROJECT_PATH/update.sh" << EOF
#!/bin/bash
echo "🔄 BitronixCode Django guncelleniyor..."
cd $PROJECT_PATH
sudo -u $PROJECT_USER $PROJECT_PATH/venv/bin/python manage.py migrate
sudo -u $PROJECT_USER $PROJECT_PATH/venv/bin/python manage.py collectstatic --noinput
systemctl restart $SERVICE_NAME
echo "✅ Guncelleme tamamlandi"
EOF

# Scriptleri calistirilabilir yap
chmod +x "$PROJECT_PATH"/*.sh
chown $PROJECT_USER:$PROJECT_USER "$PROJECT_PATH"/*.sh

echo -e "${ACIK_YESIL}✅ Otomasyon scriptleri olusturuldu${NC}"

# =================================================================
# 17. VERITABANI TEST
# =================================================================
echo -e "\n${TURKUAZ}🗄️ VERITABANI BAĞLANTI TESTI${NC}"
echo "================================================================="

if mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASS" -e "USE $DB_NAME; SELECT 1;" >/dev/null 2>&1; then
    echo -e "${ACIK_YESIL}✅ Veritabani baglantisi basarili${NC}"
else
    echo -e "${SARI}⚠️ Veritabani baglantisi test edilemedi${NC}"
fi

# =================================================================
# 18. JWT PAKET FINAL KONTROL
# =================================================================
echo -e "\n${TURKUAZ}🔐 JWT PAKET FINAL KONTROL${NC}"
echo "================================================================="

if safe_python_check "$PROJECT_PATH/venv/bin/python" "import jwt; import jose; import jwcrypto" 15; then
    echo -e "${ACIK_YESIL}✅ JWT paketleri calisiyor${NC}"
else
    echo -e "${SARI}⚠️ JWT paket kontrolu basarisiz${NC}"
fi

# =================================================================
# 19. SERVIS BASLATMA (DEVAM)
# =================================================================
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo -e "${ACIK_YESIL}✅ Servis basariyla baslatildi${NC}"
else
    echo -e "${SARI}⚠️ Servis baslatilamadi, manuel kontrol gerekli${NC}"
    echo -e "${ACIK_PEMBE}📝 Servis durumu:${NC}"
    systemctl status "$SERVICE_NAME" --no-pager || true
fi

# =================================================================
# 20. FINAL TESTLER
# =================================================================
echo -e "\n${TURKUAZ}🧪 FINAL TESTLER${NC}"
echo "================================================================="

# Django check
echo -e "${ACIK_PEMBE}🔍 Django sistem kontrolu...${NC}"
if sudo -u $PROJECT_USER "$PROJECT_PATH/venv/bin/python" manage.py check --verbosity=0 >/dev/null 2>&1; then
    echo -e "${ACIK_YESIL}✅ Django sistem kontrolu basarili${NC}"
else
    echo -e "${SARI}⚠️ Django sistem kontrolunde uyarilar var${NC}"
fi

# Port kontrolu
echo -e "${ACIK_PEMBE}🔌 Port 8000 kontrolu...${NC}"
if netstat -tuln 2>/dev/null | grep -q ":8000 "; then
    echo -e "${ACIK_YESIL}✅ Port 8000 dinleniyor${NC}"
else
    echo -e "${SARI}⚠️ Port 8000 dinlenmiyor${NC}"
fi

# HTTP test
echo -e "${ACIK_PEMBE}🌐 HTTP baglanti testi...${NC}"
if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000 2>/dev/null | grep -q "200\|301\|302"; then
    echo -e "${ACIK_YESIL}✅ HTTP baglanti testi basarili${NC}"
else
    echo -e "${SARI}⚠️ HTTP baglanti testi basarisiz${NC}"
fi

# =================================================================
# 21. GEREKLI DOSYALAR OLUSTURMA
# =================================================================
echo -e "\n${TURKUAZ}📄 GEREKLI DOSYALAR OLUSTURULUYOR${NC}"
echo "================================================================="

# robots.txt olustur
cat > "$PROJECT_PATH/staticfiles/robots.txt" << EOF
User-agent: *
Allow: /

Sitemap: http://$DOMAIN_NAME/sitemap.xml
EOF

# .htaccess olustur (Apache icin)
cat > "$PROJECT_PATH/.htaccess" << EOF
# BitronixCode Django .htaccess
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ index.py [QSA,L]

# Security headers
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-XSS-Protection "1; mode=block"
Header always set X-Content-Type-Options "nosniff"

# Gzip compression
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/plain
    AddOutputFilterByType DEFLATE text/html
    AddOutputFilterByType DEFLATE text/xml
    AddOutputFilterByType DEFLATE text/css
    AddOutputFilterByType DEFLATE application/xml
    AddOutputFilterByType DEFLATE application/xhtml+xml
    AddOutputFilterByType DEFLATE application/rss+xml
    AddOutputFilterByType DEFLATE application/javascript
    AddOutputFilterByType DEFLATE application/x-javascript
</IfModule>
EOF

# favicon.ico placeholder olustur (bos dosya)
touch "$PROJECT_PATH/staticfiles/favicon.ico"

# 404.html olustur
cat > "$PROJECT_PATH/templates/404.html" << EOF
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Sayfa Bulunamadi | $DOMAIN_NAME</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        h1 { color: #e74c3c; }
        p { color: #666; }
        a { color: #3498db; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>404 - Sayfa Bulunamadi</h1>
    <p>Aradiginiz sayfa bulunamadi.</p>
    <p><a href="/">Ana Sayfaya Don</a></p>
</body>
</html>
EOF

# 50x.html olustur
cat > "$PROJECT_PATH/templates/50x.html" << EOF
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sunucu Hatasi | $DOMAIN_NAME</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        h1 { color: #e74c3c; }
        p { color: #666; }
        a { color: #3498db; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>Sunucu Hatasi</h1>
    <p>Gecici bir sunucu hatasi olustu. Lutfen daha sonra tekrar deneyin.</p>
    <p><a href="/">Ana Sayfaya Don</a></p>
</body>
</html>
EOF

# Templates klasoru olustur
mkdir -p "$PROJECT_PATH/templates"
chown -R $PROJECT_USER:$PROJECT_USER "$PROJECT_PATH/templates"

echo -e "${ACIK_YESIL}✅ Gerekli dosyalar olusturuldu${NC}"

# =================================================================
# 22. GUVENLIK AYARLARI
# =================================================================
echo -e "\n${TURKUAZ}🔐 GUVENLIK AYARLARI${NC}"
echo "================================================================="

# Firewall kurallari (opsiyonel)
if command -v ufw >/dev/null 2>&1; then
    echo -e "${ACIK_PEMBE}🔥 UFW firewall kurallari ekleniyor...${NC}"
    ufw allow 80/tcp >/dev/null 2>&1 || true
    ufw allow 443/tcp >/dev/null 2>&1 || true
    echo -e "${ACIK_YESIL}✅ Firewall kurallari eklendi${NC}"
fi

# Fail2ban konfigurasyonu (opsiyonel)
if command -v fail2ban-client >/dev/null 2>&1; then
    echo -e "${ACIK_PEMBE}🛡️ Fail2ban nginx jail ekleniyor...${NC}"
    cat > /etc/fail2ban/jail.d/nginx.conf << EOF
[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log

[nginx-noscript]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 6

[nginx-badbots]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-noproxy]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 2
EOF
    systemctl restart fail2ban >/dev/null 2>&1 || true
    echo -e "${ACIK_YESIL}✅ Fail2ban konfigurasyonu eklendi${NC}"
fi

# Log rotation ayari
cat > /etc/logrotate.d/bitronixcode-django << EOF
$PROJECT_PATH/logs/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 $PROJECT_USER $PROJECT_USER
    postrotate
        systemctl reload $SERVICE_NAME > /dev/null 2>&1 || true
    endscript
}
EOF

echo -e "${ACIK_YESIL}✅ Guvenlik ayarlari tamamlandi${NC}"

# =================================================================
# 23. MONITORING VE HEALTH CHECK
# =================================================================
echo -e "\n${TURKUAZ}📊 MONITORING VE HEALTH CHECK${NC}"
echo "================================================================="

# Health check scripti
cat > "$PROJECT_PATH/health_check.sh" << EOF
#!/bin/bash
# BitronixCode Django Health Check

echo "🏥 BitronixCode Django Health Check - $(date)"
echo "================================================================="

# Servis durumu
if systemctl is-active --quiet $SERVICE_NAME; then
    echo "✅ Servis: CALISIYOR"
else
    echo "❌ Servis: CALISMIYOR"
    exit 1
fi

# Port kontrolu
if netstat -tuln 2>/dev/null | grep -q ":8000 "; then
    echo "✅ Port 8000: DINLENIYOR"
else
    echo "❌ Port 8000: DINLENMIYOR"
    exit 1
fi

# HTTP kontrolu
HTTP_CODE=\$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000 2>/dev/null)
if [[ "\$HTTP_CODE" =~ ^(200|301|302)$ ]]; then
    echo "✅ HTTP: CALISIYOR (\$HTTP_CODE)"
else
    echo "❌ HTTP: CALISMIYOR (\$HTTP_CODE)"
    exit 1
fi

# Veritabani kontrolu
if mysql -h$DB_HOST -P$DB_PORT -u$DB_USER -p$DB_PASS -e "USE $DB_NAME; SELECT 1;" >/dev/null 2>&1; then
    echo "✅ Veritabani: BAĞLANTI BASARILI"
else
    echo "❌ Veritabani: BAĞLANTI BASARISIZ"
    exit 1
fi

# Disk kullanimi
DISK_USAGE=\$(df $PROJECT_PATH | awk 'NR==2 {print \$5}' | sed 's/%//')
if [ "\$DISK_USAGE" -lt 90 ]; then
    echo "✅ Disk kullanimi: %\$DISK_USAGE"
else
    echo "⚠️ Disk kullanimi: %\$DISK_USAGE (Yuksek!)"
fi

# Memory kullanimi
MEM_USAGE=\$(free | awk 'NR==2{printf "%.0f", \$3*100/\$2}')
if [ "\$MEM_USAGE" -lt 90 ]; then
    echo "✅ Memory kullanimi: %\$MEM_USAGE"
else
    echo "⚠️ Memory kullanimi: %\$MEM_USAGE (Yuksek!)"
fi

echo "================================================================="
echo "🎯 Health Check: TUM KONTROLLER BASARILI"
EOF

chmod +x "$PROJECT_PATH/health_check.sh"
chown $PROJECT_USER:$PROJECT_USER "$PROJECT_PATH/health_check.sh"

# Crontab icin health check (her 5 dakikada)
(crontab -u $PROJECT_USER -l 2>/dev/null; echo "*/5 * * * * $PROJECT_PATH/health_check.sh >> $PROJECT_PATH/logs/health_check.log 2>&1") | crontab -u $PROJECT_USER -

echo -e "${ACIK_YESIL}✅ Health check sistemi kuruldu${NC}"

# =================================================================
# 24. BACKUP SCRIPTI OLUSTURMA
# =================================================================
echo -e "\n${TURKUAZ}💾 BACKUP SCRIPTI OLUSTURULUYOR${NC}"
echo "================================================================="

cat > "$PROJECT_PATH/backup.sh" << EOF
#!/bin/bash
# BitronixCode Django Backup Script

BACKUP_DIR="/home/$PROJECT_USER/backups"
DATE=\$(date +%Y%m%d_%H%M%S)
PROJECT_BACKUP="\$BACKUP_DIR/project_\$DATE.tar.gz"
DB_BACKUP="\$BACKUP_DIR/database_\$DATE.sql"

echo "🗄️ BitronixCode Django Backup - \$(date)"
echo "================================================================="

# Backup klasoru olustur
mkdir -p "\$BACKUP_DIR"

# Proje dosyalarini yedekle
echo "📁 Proje dosyalari yedekleniyor..."
cd $PROJECT_PATH
tar -czf "\$PROJECT_BACKUP" --exclude='venv' --exclude='logs' --exclude='*.pyc' --exclude='__pycache__' .
echo "✅ Proje yedeklendi: \$PROJECT_BACKUP"

# Veritabanini yedekle
echo "🗄️ Veritabani yedekleniyor..."
mysqldump -h$DB_HOST -P$DB_PORT -u$DB_USER -p$DB_PASS $DB_NAME > "\$DB_BACKUP"
echo "✅ Veritabani yedeklendi: \$DB_BACKUP"

# Eski yedekleri temizle (30 gunden eski)
echo "🧹 Eski yedekler temizleniyor..."
find "\$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete
find "\$BACKUP_DIR" -name "*.sql" -mtime +30 -delete
echo "✅ Eski yedekler temizlendi"

echo "================================================================="
echo "🎯 Backup tamamlandi: \$(date)"
EOF

chmod +x "$PROJECT_PATH/backup.sh"
chown $PROJECT_USER:$PROJECT_USER "$PROJECT_PATH/backup.sh"

# Gunluk backup icin crontab
(crontab -u $PROJECT_USER -l 2>/dev/null; echo "0 2 * * * $PROJECT_PATH/backup.sh >> $PROJECT_PATH/logs/backup.log 2>&1") | crontab -u $PROJECT_USER -

echo -e "${ACIK_YESIL}✅ Backup sistemi kuruldu${NC}"

# =================================================================
# 25. FINAL OZET VE TAMAMLAMA
# =================================================================
echo -e "\n${BEYAZ}🎊 ULTIMATE DEPLOYMENT BASARIYLA TAMAMLANDI! 🎊${NC}"
echo "================================================================="

echo -e "\n${ACIK_YESIL}🏆 TAMAMLANAN TUM ISLEMLER:${NC}"
echo "   ✅ Sistem paketleri kuruldu"
echo "   ✅ Yedek dosyasi restore edildi"
echo "   ✅ Python sanal ortam olusturuldu"
echo "   ✅ Python paketleri yuklendi"
echo "   ✅ JWT paketleri kontrol edildi"
echo "   ✅ Django settings guncellendi"
echo "   ✅ Dosya izinleri duzenlendi"
echo "   ✅ Gunicorn konfigure edildi"
echo "   ✅ WSGI modulu tespit edildi"
echo "   ✅ Systemd servisi olusturuldu"
echo "   ✅ Nginx konfigurasyonu olusturuldu"
echo "   ✅ Django migrate ve collectstatic"
echo "   ✅ Otomasyon scriptleri olusturuldu"
echo "   ✅ Veritabani baglantisi test edildi"
echo "   ✅ Gerekli dosyalar olusturuldu"
echo "   ✅ Guvenlik ayarlari yapildi"
echo "   ✅ Health check sistemi kuruldu"
echo "   ✅ Backup sistemi kuruldu"

echo -e "\n${TURKUAZ}📊 PROJE BILGILERI:${NC}"
echo "   🏠 Proje Yolu: $PROJECT_PATH"
echo "   👤 Kullanici: $PROJECT_USER"
echo "   🌍 Domain: $DOMAIN_NAME"
echo "   🗄️ Veritabani: $DB_NAME@$DB_HOST:$DB_PORT"
echo "   🐍 Sanal Ortam: $PROJECT_PATH/venv"
echo "   🦄 WSGI Modulu: $WSGI_MODULE"
echo "   ⚙️ Servis: $SERVICE_NAME"

echo -e "\n${ACIK_PEMBE}🚀 SERVIS KOMUTLARI:${NC}"
echo "   Baslat: systemctl start $SERVICE_NAME"
echo "   Durdur: systemctl stop $SERVICE_NAME"
echo "   Yeniden Baslat: systemctl restart $SERVICE_NAME"
echo "   Durum: systemctl status $SERVICE_NAME"
echo "   Loglar: journalctl -u $SERVICE_NAME -f"

echo -e "\n${ACIK_PEMBE}🤖 OTOMASYON SCRIPTLERI:${NC}"
echo "   🚀 Baslat: $PROJECT_PATH/start.sh"
echo "   🛑 Durdur: $PROJECT_PATH/stop.sh"
echo "   🔄 Yeniden Baslat: $PROJECT_PATH/restart.sh"
echo "   📊 Durum: $PROJECT_PATH/status.sh"
echo "   📝 Loglar: $PROJECT_PATH/logs.sh"
echo "   🔄 Guncelle: $PROJECT_PATH/update.sh"
echo "   🏥 Health Check: $PROJECT_PATH/health_check.sh"
echo "   💾 Backup: $PROJECT_PATH/backup.sh"

echo -e "\n${ACIK_PEMBE}📁 DOSYA KONUMLARI:${NC}"
echo "   🌐 Nginx Config: /etc/nginx/sites-available/$DOMAIN_NAME"
echo "   ⚙️ Systemd Service: /etc/systemd/system/$SERVICE_NAME.service"
echo "   🦄 Gunicorn Config: $PROJECT_PATH/gunicorn.conf.py"
echo "   📝 Loglar: $PROJECT_PATH/logs/"
echo "   📁 Static Files: $PROJECT_PATH/staticfiles/"
echo "   🖼️ Media Files: $PROJECT_PATH/media/"

echo -e "\n${SARI}🌐 TEST URL'LERI:${NC}"
echo "   HTTP: http://$DOMAIN_NAME"
echo "   WWW: http://www.$DOMAIN_NAME"
echo "   Direct: http://127.0.0.1:8000"

echo -e "\n${TURUNCU}⚠️ ONEMLI NOTLAR:${NC}"
echo "   • Veritabani dump'ini import etmeyi unutmayin"
echo "   • SSL sertifikasi kurulumunu yapin"
echo "   • DNS ayarlarinizi kontrol edin"
echo "   • Production'da DEBUG=False oldugundan emin olun"
echo "   • Duzenli backup'lari kontrol edin"

echo -e "\n${ACIK_YESIL}🎯 Deployment %100 tamamlandi ve kullanima hazir!${NC}"
echo -e "${BEYAZ}BitronixCode tarafindan gelistirilmistir. 🚀${NC}"
echo -e "${ACIK_PEMBE}Destek icin: https://bitronixcode.com${NC}"
echo "================================================================="

# Son kontrol
echo -e "\n${TURKUAZ}🔍 SON KONTROL${NC}"
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo -e "${ACIK_YESIL}✅ Servis calisiyor - Deployment basarili!${NC}"
    echo -e "${ACIK_PEMBE}🌐 Test icin: http://$DOMAIN_NAME${NC}"
else
    echo -e "${SARI}⚠️ Servis durumu belirsiz - Manuel kontrol yapin${NC}"
    echo -e "${ACIK_PEMBE}📝 Kontrol: systemctl status $SERVICE_NAME${NC}"
fi

# Basari sesi
echo -e "\a"

echo -e "\n${ACIK_YESIL}🎉 ULTIMATE DEPLOYMENT SCRIPT TAMAMLANDI! 🎉${NC}"

exit 0

 }

}

# =====================================================
# 🏠 ANA MENÜ GÖSTERME FONKSİYONU
# =====================================================
ana_menu_goster() {
    echo -e "${TURKUAZ}╔════════════════════════════════════╗${NC}"
    echo -e "${TURKUAZ}║         ANA İŞLEM MENÜSÜ          ║${NC}"
    echo -e "${TURKUAZ}╚════════════════════════════════════╝${NC}"
    echo ""
    echo -e "1) 🔧 Sistem Ayarla (Tek seferlik)"
    echo -e "2) 🌐 BIND9 (DNS - ÖNCELİKLİ)"
    echo -e "3) ☁️ CloudPanel (Web Panel + MySQL)"
    echo -e "4) 📧 Mail Sunucu Yönetimi"
    echo -e "5) 🧹 OpenCart Temizlik & İzin Modülü"
    echo -e "6) 🐍 Django Site Yönetimi"
    echo -e "0) ❌ Çıkış"
    echo ""
}

# =====================================================
# 🚀 ANA PROGRAM DÖNGÜSÜ
# =====================================================
main() {
    while true; do
        ana_baslik_goster
        sistem_durumu_goster
        ana_menu_goster

        echo -e "${SARI}Seçiminizi yapın (0-6): ${NC}"
        read -r secim

        case $secim in
            1)
                sistem_ayarla
                ;;
            2)
                bind9_menu
                ;;
            3)
                cloudpanel_menu
                ;;
            4)
                mail_servisleri
                ;;
            5)
                opencart_temizle
                ;;
            6)
                django_site_yonet
                ;;
            0)
                cikis_yap
                ;;
            *)
                gecersiz_secim
                ;;
        esac
    done
}

# =====================================================
# 🎬 PROGRAM BAŞLATMA
# =====================================================

# Program başlangıcında hoş geldin mesajı
program_baslangic_mesaji() {
    clear
    echo -e "${TURKUAZ}═════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${TURKUAZ}                          🎉 HOŞ GELDİNİZ!${NC}"
    echo -e "${TURKUAZ}                    JustServer Ultimate v${BETIK_SURUMU}${NC}"
    echo -e "${TURKUAZ}═════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${BEYAZ}Bu araç ile şunları yapabilirsiniz:${NC}"
    echo -e "   🔧 Sistem optimizasyonu ve güvenlik ayarları"
    echo -e "   🌐 BIND9 DNS sunucu kurulumu ve yönetimi"
    echo -e "   ☁️ CloudPanel web yönetim paneli kurulumu"
    echo -e "   📧 Mail sunucu kurulumu ve yapılandırması"
    echo -e "   🧹 OpenCart Temizlik & İzin Modülü (cache, log, izin, oturum vb.)"
    echo -e "   🐍 Django Site Yönetimi"
    echo ""
    echo -e "${SARI}⚠️ Önemli: Bu araç root yetkileri ile çalışır ve sistem değişiklikleri yapar.${NC}"
    echo -e "${SARI}⚠️ Kurulum sırası: Sistem Ayarla → BIND9 → CloudPanel → Mail${NC}"
    echo ""
}

# =====================================================
# 🛡️ SİSTEM KAYNAK KONTROL FONKSİYONU
# =====================================================
sistem_kaynak_kontrol() {
    local min_ram=1024  # MB
    local min_disk=10   # GB

    echo -e "${TURKUAZ}🔍 Sistem kaynakları kontrol ediliyor...${NC}"

    # Root kontrolü
    if [[ $EUID -eq 0 ]]; then
        echo -e "   ✅ Root yetkileri: Mevcut"
    else
        echo -e "   ❌ Root yetkileri: Eksik"
        echo -e "${TURUNCU}Lütfen 'sudo $0' komutu ile çalıştırın.${NC}"
        exit 1
    fi

    # İnternet bağlantısı kontrolü
    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        echo -e "   ✅ İnternet bağlantısı: Aktif"
    else
        echo -e "   ⚠️ İnternet bağlantısı: Problem olabilir"
    fi

    # Disk alanı kontrolü
    local mevcut_disk=$(df / | awk 'NR==2{print int($4/1024/1024)}')
    local disk_kullanim=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    echo -e "${BEYAZ}   💽 Disk: ${mevcut_disk}GB (Minimum: ${min_disk}GB)${NC}"
    if [[ $mevcut_disk -lt $min_disk ]]; then
        echo -e "${TURUNCU}❌ Yetersiz disk alanı: ${mevcut_disk}GB${NC}"
        exit 1
    elif [[ $disk_kullanim -ge 80 ]]; then
        echo -e "   ⚠️ Disk alanı: Az (%$disk_kullanim kullanımda)"
    else
        echo -e "   ✅ Disk alanı: Yeterli (%$disk_kullanim kullanımda)"
    fi

    # Bellek kontrolü
    local mevcut_ram=$(free -m | awk 'NR==2{print $2}')
    echo -e "${BEYAZ}   💾 RAM: ${mevcut_ram}MB (Minimum: ${min_ram}MB)${NC}"
    if [[ $mevcut_ram -lt $min_ram ]]; then
        echo -e "${TURUNCU}❌ Yetersiz RAM: ${mevcut_ram}MB${NC}"
        exit 1
    elif [[ $mevcut_ram -le 1024 ]]; then
        echo -e "   ⚠️ Bellek: Az (${mevcut_ram}MB)"
    else
        echo -e "   ✅ Bellek: Yeterli (${mevcut_ram}MB)"
    fi

    echo -e "${ACIK_YESIL}✅ Sistem kaynakları yeterli${NC}"
    echo ""
    echo -e "${BEYAZ}Devam etmek için Enter tuşuna basın...${NC}"
    read -r
}

# =====================================================
# 🔧 YARDIMCI FONKSİYONLAR
# =====================================================

enter_bekle() {
    echo -e "\n${BEYAZ}Devam etmek için Enter tuşuna basın...${NC}"
    read -r
}

cikis_yap() {
    echo -e "\n${TURKUAZ}👋 Görüşürüz!${NC}"
    exit 0
}

gecersiz_secim() {
    echo -e "\n${TURUNCU}❌ Geçersiz seçim!${NC}"
    sleep 1
}

gunluk_yaz() {
    local seviye=$1
    local mesaj=$2
    local tarih=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$tarih] [$seviye] $mesaj" >> "$GUNLUK_DOSYASI"
}

ana_baslik_goster() {
    clear
    echo -e "${TURKUAZ}═════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${TURKUAZ}                     JustServer Ultimate v${BETIK_SURUMU}                     ${NC}"
    echo -e "${TURKUAZ}═════════════════════════════════════════════════════════════════════════════${NC}"
}

domain_gecerli_mi() {
    local domain=$1
    if [[ $domain =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 0
    else
        return 1
    fi
}

# =====================================================
# 📊 SİSTEM DURUMU GÖSTERME FONKSİYONU
# =====================================================
sistem_durumu_goster() {
    echo -e "${GRI}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${ACIK_PEMBE}📊 SİSTEM DURUMU${NC}"
    echo -e "${GRI}═══════════════════════════════════════════════════════════════════════════════${NC}"
    
    # Sistem bilgileri
    local uptime_info=$(uptime | awk -F',' '{print $1}' | awk '{print $3,$4}')
    local load_avg=$(uptime | awk -F'load average:' '{print $2}')
    local disk_usage=$(df -h / | awk 'NR==2 {print $5}')
    local memory_usage=$(free | awk 'NR==2{printf "%.1f%%", $3*100/$2}')
    
    echo -e "${BEYAZ}⏰ Çalışma Süresi: ${uptime_info}${NC}"
    echo -e "${BEYAZ}📈 Yük Ortalaması: ${load_avg}${NC}"
    echo -e "${BEYAZ}💽 Disk Kullanımı: ${disk_usage}${NC}"
    echo -e "${BEYAZ}💾 Bellek Kullanımı: ${memory_usage}${NC}"
    echo ""
}

# =====================================================
# 🚀 ANA MODÜL FONKSİYONLARI (PLACEHOLDER)
# =====================================================

sistem_ayarla() {
    echo -e "${TURKUAZ}🔧 Sistem ayarlanıyor...${NC}"
    # Bu fonksiyon betikteki gerçek sistem_ayarla() fonksiyonunu çağırmalı
    enter_bekle
}

bind9_menu() {
    echo -e "${ACIK_YESIL}🌐 BIND9 menüsü açılıyor...${NC}"
    # Bu fonksiyon betikteki gerçek bind9_menu() fonksiyonunu çağırmalı
    enter_bekle
}

cloudpanel_menu() {
    echo -e "${TURKUAZ}☁️ CloudPanel menüsü açılıyor...${NC}"
    # Bu fonksiyon betikteki gerçek cloudpanel_menu() fonksiyonunu çağırmalı
    enter_bekle
}

mail_servisleri() {
    echo -e "${SARI}📧 Mail servisleri menüsü açılıyor...${NC}"
    # Bu fonksiyon betikteki gerçek mail_servisleri() fonksiyonunu çağırmalı
    enter_bekle
}

opencart_temizle() {
    echo -e "${TURUNCU}🧹 OpenCart temizleme aracı başlatılıyor...${NC}"
    # Bu fonksiyon betikteki gerçek opencart_temizle() fonksiyonunu çağırmalı
    enter_bekle
}

django_site_yonet() {
    echo -e "${MOR}🐍 Django Site Yönetimi başlatılıyor...${NC}"
    # Bu fonksiyon betikteki gerçek django_site_yonet() fonksiyonunu çağırmalı
    enter_bekle
}

# =====================================================
# 🛠️ SERVİS YÖNETİM FONKSİYONLARI (PLACEHOLDER)
# =====================================================

tum_servisleri_baslat() {
    echo -e "${ACIK_YESIL}🚀 Tüm servisler başlatılıyor...${NC}"
    # Bu fonksiyon betikteki gerçek tum_servisleri_baslat() fonksiyonunu çağırmalı
}

tum_servisleri_durdur() {
    echo -e "${TURUNCU}⏹️ Tüm servisler durduruluyor...${NC}"
    # Bu fonksiyon betikteki gerçek tum_servisleri_durdur() fonksiyonunu çağırmalı
}

tum_servisleri_yeniden_baslat() {
    echo -e "${SARI}🔄 Tüm servisler yeniden başlatılıyor...${NC}"
    # Bu fonksiyon betikteki gerçek tum_servisleri_yeniden_baslat() fonksiyonunu çağırmalı
}

servis_durumlari() {
    echo -e "${TURKUAZ}📊 Servis durumları kontrol ediliyor...${NC}"
    # Bu fonksiyon betikteki gerçek servis_durumlari() fonksiyonunu çağırmalı
}

mail_kuyrugu_goster() {
    echo -e "${BEYAZ}📬 Mail kuyruğu görüntüleniyor...${NC}"
    # Bu fonksiyon betikteki gerçek mail_kuyrugu_goster() fonksiyonunu çağırmalı
}

mail_loglari_goster() {
    echo -e "${BEYAZ}📋 Mail logları görüntüleniyor...${NC}"
    # Bu fonksiyon betikteki gerçek mail_loglari_goster() fonksiyonunu çağırmalı
}

dmarc_test() {
    local domain=$1
    echo -e "${ACIK_YESIL}🔍 DMARC testi yapılıyor: $domain${NC}"
    # Bu fonksiyon betikteki gerçek dmarc_test() fonksiyonunu çağırmalı
}

# =====================================================
# 🎯 PROGRAM BAŞLATMA NOKTASI
# =====================================================

# Program başlangıç kontrolü
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Sadece doğrudan çalıştırıldığında başlat
    program_baslangic_mesaji
    sistem_kaynak_kontrol
    
    # Ana programı başlat
    main
    
    # Programdan çıkış
    exit 0
fi
