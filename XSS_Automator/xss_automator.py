
import sys
import urllib
import urllib.request

direccion_input = input("Introduzca la dirección a analizar: ")
fichero= open("ataques.txt","r")
#Leemos los primeros 8 caracteres para comprobar si comienza en http
comprueba_http = str(direccion_input[0:7])
comprueba_https = str(direccion_input[0:8])
#Si la URL no comienza por http nos mostraría un error, de modo que si detecta que no comienza así, introducirá en la url http://
if (comprueba_http=='http://' or comprueba_https=='https://'):
	direccion_modificada = direccion_input
#Si no comienza por http o https, añadimos http al comienzo de la url
else:
	direccion_modificada = 'http://'+direccion_input

#recorremos cada una de las lineas del fichero que almacena cada uno de los ataques
for linea in fichero:
	try:	
		#añadimos a la url la injeccion xss para realizar la peticion
		ataque = direccion_modificada + linea
		#abrimos la url
		resp = urllib.request.urlopen(ataque)
		#leemos la respuesta
		body = resp.read()
		#la codificamos en utf-8
		respuesta = body.decode('utf-8')
		#print (respuesta)
		print ('*************************************************************************************')
		print ('Comprobando ataque: '+ linea+ '')
		print ('*************************************************************************************')
		
		
		#Pasamos todo el html a minusculas, por si hemos utilizado alguna tecnica de introducir mayusculas en el ataque, en caso de que detecte el script mostrará la alerta
		if "<script>alert('xss')</script>" in respuesta.lower():
        		print ("Se ha detectado que el dominio es vulnerable a XSS con el ataque: " + ataque)
        		break
		#En caso contrario indica que no es vulnerable
		else:
        		print ("No es vulnerable")
	except:
		print("Error, la URL que estás introduciendo NO es susceptible a ataques")
		break
#cerramos el fichero	
fichero.close()

