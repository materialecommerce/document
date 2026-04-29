1 - Detectar possíveis ataques de XSS (Cross-Site Scripting)

Comando utilizado:

grep -iE "<script|%3Cscript" access.log

- Tentativa de acesso a diversos endpoints sem sucesso - 404 - em algo como list.php, plugins etc. O invasor tentou encontrar vunerabilidades usando "script|%3Cscript"

172.17.0.3 - - [19/Jul/2024:00:15:43 -0300] "GET /properties-list.php?property-types=1&types=2&location&prices&bedroom&code=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1" 404 456 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36"
172.17.0.3 - - [19/Jul/2024:00:15:46 -0300] "GET /wp-content/plugins/ellipsis-human-presence-technology/inc/protected-forms-table.php?page=%22%20%3E%3Cscript%3Ealert(document.location)%3C/script%3E HTTP/1.1" 404 456 "-" "Mozilla/5.0 (X11; Linux i686; rv:126.0) Gecko/20100101 Firefox/126.0"
172.17.0.3 - - [19/Jul/2024:00:15:46 -0300] "GET /wp-content/plugins/portrait-archiv-shop/js/imageDetails.php?pDetails=);});%3C/script%3E%3Cscript%3Ealert(document.location)%3C/script%3E HTTP/1.1" 404 456 "-" "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0"
172.17.0.3 - - [19/Jul/2024:00:15:46 -0300] "GET /wp-content/plugins/qwiz-online-quizzes-and-flashcards/registration_complete.php?qname=%3C/script%3E%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1" 404 456 "-" "Mozilla/5.0 (Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36



2 - Detectar tentativas de SQL Injection


Comando utilizado: grep -iE "union|select|insert|drop|%27|%22" access.log

- Tentativa de acesso ao banco de dados SQL - resultado: 200 ( com sucesso ).

172.17.0.6 - - [19/Jul/2024:00:55:59 -0300] "GET /?fuzz=test&TWbZ=3606%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23 HTTP/1.1" 200 3343 "-" "sqlmap/1.6.4#stable (https://sqlmap.org)"


3 - Detectar varredura de diretórios (Directory Traversal)


Comando utilizado: grep -E "\.\./|\.\.%2f" access.log

- Tentativa de acesso ROOT ao servidor apache

172.17.0.3 - - [19/Jul/2024:00:15:44 -0300] "POST /seeyon/wpsAssistServlet?flag=save&realFileType=../../../../ApacheJetspeed/webapps/ROOT/2jtRRb.jsp&fileId=2 HTTP/1.1" 404 456 "-" "Mozilla/5.0 (Debian; Linux i686; rv:125.0) Gecko/20100101 Firefox/125.0"


4 - Detectar possíveis ataques por scanners (User-Agent suspeito)


Comando utilizado: grep -iE "nikto|nmap|sqlmap|acunetix|curl|masscan|python" access.log

- Tentativa de explorar falhas no servidor como o NMAP pra ter acessos confidenciais em diretórios do servidor como password/senha.

172.17.0.3 - - [19/Jul/2024:00:10:23 -0300] "GET /CFIDE/administrator/enter.cfm?locale=..\\..\\..\\..\\..\\..\\..\\..\\CFusionMX\\lib\\password.properties%00en HTTP/1.1" 404 456 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"


5 - Identificar tentativas de acesso a arquivos sensíveis (.env, .git, etc.)

Comando utilizado: grep -iE "\.env|\.git|\.htaccess|\.bak" access.log

 - Tentativa de acessar arquivos do diretório do servidor, incluindo wp.config.php, que fica na raiz do diretório e possui dados sensíveis

172.17.0.3 - - [19/Jul/2024:00:26:06 -0300] "GET /archives.bak HTTP/1.1" 404 491 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"

172.17.0.3 - - [19/Jul/2024:00:15:46 -0300] "GET /wp-config.php.bak HTTP/1.1" 404 456 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363"
172.17.0.3 - - [19/Jul/2024:00:15:46 -0300] "GET /wp-config.php.BAK HTTP/1.1" 404 456 "-" "Mozilla/5.0 (ZZ; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0"


6 - Detectar possíveis ataques de força bruta a arquivos/pastas

Comando utilizado: grep " 404 " access.log | cut -d " " -f 1 | sort | uniq -c | sort -nr | head


- Quantidade de "requests" incomum, ip's suspeitos de tentativa forçada de acesso, sem sucesso "404", com destaque para "172.17.0.3" e "172.17.0.2" 

 106619 172.17.0.3
   6463 172.17.0.2
      2 172.17.0.6
      2 172.17.0.4
      1 172.17.0.5



7 -  Primeiro e ultimo acesso de um IP suspeito.


Comandos utilizados:  grep "172.17.0.3" access.log | head -n1 && grep "172.17.0.3" access.log | tail -n1

- O acesso do IP suspeito foi entre 00:08:27 a 00:27:27, resultando em um total de 19 minutos. 


172.17.0.3 - - [19/Jul/2024:00:08:27 -0300] "GET / HTTP/1.1" 200 11012 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
172.17.0.3 - - [19/Jul/2024:00:27:27 -0300] "GET /~~-jobs.html HTTP/1.1" 404 492 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"


8 - Localizar user-agent utilizado por um IP suspeito


Comando utilizado: grep "172.17.0.3" access.log | cut -d '"' -f 6 | sort | uniq


- O suspeito pode estar tentando uma automação de exploits, teste de invasão ou mesmo web scraping intensivo de dados


python-requests/2.26.0



9 - Listar os ips e verificar o numero de requisições.


Comando utilizado: cat access.log | cut -d " " -f 1 | sort | uniq -c


     63 ::1
   6464 172.17.0.2
 107846 172.17.0.3
     10 172.17.0.4
     60 172.17.0.5
     81 172.17.0.6
      2 172.26.109.205
      7 172.26.96.1


10- Localizar acesso a um determinado arquivo sensível


Comando utilizado: grep "passwords" access.log


- Acesso ao banco de dados de senhas.

172.17.0.3 - - [19/Jul/2024:00:08:34 -0300] "GET /passwords.xml HTTP/1.1" 404 492 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
172.17.0.3 - - [19/Jul/2024:00:08:34 -0300] "GET /passwords.json HTTP/1.1" 404 492 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"

