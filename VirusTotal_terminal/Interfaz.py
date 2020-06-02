# -*- coding: utf-8 -*-

from fpdf import FPDF
from ipwhois import IPWhois
import msvcrt as m
import os, sys, requests, hashlib, urllib, json, time, socket, logging, sqlite3
import json, argparse, hashlib, re, sys, urllib.parse, urllib.request, requests
from pprint import pprint


# Crear la tabla
try:
	#Conectarse a la Base de datos
	bd = sqlite3.connect("database/bd_local.db")
	#Creamos un cursor para poder interactuar con la Base de Datos
	cursor = bd.cursor() 
	tablas = [
		"""
			CREATE TABLE IF NOT EXISTS amenazas(
				md5 TEXT NOT NULL,
				texto TEXT NOT NULL,
				PRIMARY KEY(md5)
			);
		"""
	]
	for tabla in tablas:
		cursor.execute(tabla);
except sqlite3.OperationalError as error:
	print("Error al abrir:", error)



#Si pusieramos level=logging.DEBUG nos mostraria las peticiones GET y POST que realizamos, pero ahora solo nos interesa los INFO que he creado
logging.basicConfig(filename='logs/aplication.log',level=logging.INFO,format='[%(asctime)s] %(message)s',datefmt='%m/%d/%Y %I:%M:%S %p')
logging.info('Se ha inicializado la aplicación')

#VARIABLES GLOBALES
global name, var, var1, direccionFichero


class mensajes():
    def inicio(self):
        print ("Bienvenido/a")
        #MOSTRAMOS EL NUMERO DE MD5 QUE POSEE ALMACENADA NUESTRA BD LOCAL
        cursor.execute("""SELECT COUNT(*) FROM amenazas""")
        amenaza = cursor.fetchone()
        print("La base de datos local posee "+ str(amenaza[0]) +" MD5 registrados")
    
    def menu(self):
        print ("Selecciona una opción")
        print ("\t1 - Análisis de un MD5")
        print ("\t2 - Análisis de una URL")
        print ("\t3 - WHOIS URL")
        print ("\t4 - Análisis de un Fichero")
        print ("\t9 - salir")

#######################
#CLASE API VIRUS TOTAL#
#######################
class apiVirusTotal():

    ##########################
    #     FUNCION INCIAL     #
    ##########################
    def __init__(self):
        #API PUBLICA 
        self.api='' # DEBERÁN INTRODUCIR LA API QUE VIRUSTOTAL LES OTORGUE
        self.base = 'https://www.virustotal.com/vtapi/v2/'

    ##########################
    #   FUNCIONES GENERALES  #
    ##########################

    # FUNCION EXPORTAR A PDF
    def exportPDF(self,result,tipo):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.write(5,result)
        if (tipo == "fichero"):
            pdf.output("reports/ficheros/file_report_"+time.strftime('%d%m%y_%H%M%S')+".pdf")
            logging.info('Se ha creado un informe de un fichero ')
        if (tipo =="url"):
            pdf.output("reports/urls/url_report"+time.strftime('%d%m%y_%H%M%S')+".pdf")
            logging.info('Se ha creado un informe de una URL')



    ##########################
    #   FUNCIONES FICHERO    #
    ##########################

    # FUNCION QUE DEVUELVE EL VALOR DE LA CONSULTA SOLICITADA
    def returnjdata(self,md5):
        param = {'resource':md5,'apikey':self.api}
        url = self.base + "file/report"
        data = urllib.parse.urlencode(param).encode("utf-8")
        req = urllib.request.Request(url)
        result = urllib.request.urlopen(req,data)
        jdata =  json.loads(result.read())
        return jdata

    # FUNCION QUE COMPRUEBA SI EL FICHERO INTRODUCIDO APARECE REGISTRADO EN LA BD DE VIRUS TOTAL A TRAVES DE SU MD5 Y EN CASO CONTRARIO LO REGISTRA PARA SU COMPROBACION
    def getReport(self,md5,rutaFichero):
        #label2.pack_forget()
        vt = apiVirusTotal()
        #DEBEMOS COMPROBAR EN LA BASE DE DATOS LOCAL SI EL MD5 QUE ESTAMOS BUSCANDO YA ESTÁ ALMACENADO
        cursor.execute("""SELECT COUNT(*) FROM amenazas WHERE md5=?""",(md5.lower(),))
        amenaza = cursor.fetchone()
        # Si el resultado de la consulta nos devuelve el valor "0" significará que este valor no se encuentra almacenado en la base de datos local
       
        if (amenaza[0]==0):
        	print("Aún no ha sido registrada en la BD")
        	#Llamamos a la clase para tener acceso a todas las funciones
        	
        	jdata = vt.returnjdata(md5)

        	# Si el md5 del fichero subido no está registrado en la BD de VirusTotal debemos indicar que aún no aparece y lo registraremos nosotros para comprobarlo
        	if jdata['response_code'] == 0:
        		print (md5 + "-- No se ha encontrado en virustotal")
        		logging.info('Analisis Fichero: El md5 no ha sido localizado en la BD de VirusTotal')
        		print ("Subiendo fichero...")
        		logging.info('Analisis Fichero: Se esta subiendo el fichero')
        		#Registramos el fichero
        		vt.analizarFichero(rutaFichero)
        		#Solicitamos el informe
        		print("Actualizando la BD de VirusTotal...")
        		logging.info('Analisis Fichero: Peticion actualización BD VirusTotal')
        		#print ("El MD5 es "+ md5)
        		vt.updateReport(md5)
        	# En caso de que si que exista mostramos el resultado del análisis. Debemos tener en cuenta este punto, porque puede que nuestra BD local no almacene el resultado
        	# pero la API de VirusTotal probablemente haya analizado este fichero.
        	else:
        		vt.muestraInforme(jdata)

        # En el caso de que se haya encontrado este md5 en la base de datos local nos mostrará el resultado que tenemos almacenado en nuestra base de datos
        # Sería interesante que nos diera la opción de analizar de nuevo en la API de VirusTotal
        # En principio unicamente  se podrá registrar el md5 una única vez (asignamos el md5 como PRIMARY KEY), en caso de que hubiera algún cambio
        # se quisiera analizar de nuevo en la API de VirusTotal, podríamos actualizar la inserción en la base de datos local con un UPDATE
        else:
        	#print ("Este md5 aparece en la BD " + str(amenaza[0]) + "veces")
        	cursor.execute("""SELECT * FROM amenazas WHERE md5=?""",(md5.lower(),))
        	amenaza = cursor.fetchall()
        	for md5,texto in amenaza:
        		result = texto

        	print (result)
        	

             
        

    #FUNCION QUE SUBE EL FICHERO A LA BD DE VIRUS TOTAL
    def analizarFichero(self,rutaFichero):
        url = self.base + "file/scan"
        param = {'apikey': self.api}
        files = {'file': (rutaFichero, open(rutaFichero, 'rb'))}
        response = requests.post(url, files=files, params=param)
        print ("Fichero subido con exito")
        logging.info('Analisis Fichero: Se ha subido el fichero')

   	#FUNCION PARA REANALIZAR UN FICHERO QUE YA ESTABA ALMACENADO EN LA BD DE VIRUSTOTAL
    def reanalizarFichero(self,rutaFichero):
    	url = self.base + "file/rescan"
    	param = {'apikey': self.api}
    	files = {'file': (rutaFichero, open(rutaFichero, 'rb'))}
    	response = requests.post(url, files=files, params=param)
    	print ("Fichero subido con exito")
    	logging.info('Analisis Fichero: Se ha subido el fichero')

    # FUNCION QUE COMPRUEBA SI SE HA ACTUALIZADO YA LA BASE DE DATOS DE VIRUS TOTAL CON EL DATO INTRODUCIDO
    def updateReport(self,md5):
        vt = apiVirusTotal()
        jdata = vt.returnjdata(md5)
        
        #print (jdata)
        # Si la primera vez que solicitamos actualizar el reporte obtenemos "1" significará que este fichero ya estaba analizado y por tanto debemos ir consultando
        # a la API hasta que el la fecha del escaner jdata['scan_date'] sea posterior a la que tenía almacenada anteriormente en la base de datos
        if(str(jdata['response_code']) == "1"):
        	print("Este fichero ya estaba subido en fecha "+ jdata['scan_date'])
        	last_scan = jdata['scan_date']
        	actual_scan = jdata['scan_date']
        	while (last_scan == actual_scan):
        		jdata = vt.returnjdata(md5)
        		actual_scan = jdata['scan_date']
        		#print ("LAST SCAN "+ last_scan + (" ACTUAL SCAN "+ actual_scan))
        		time.sleep(1)
       		print ("Fecha actual: "+ jdata['scan_date'])

        else:     # En caso contrario significará que este fichero nunca ha sido analizado y por lo tanto tenemos que ir consultando hasta obtener el resultado final (response_code == 1)

        	# Si el response_code es -2 nos indica que "Your resource is queued for analysis", es decir, que está en cola para ser analizado, por tanto debemos esperar
        	while(str(jdata['response_code']) == "-2"):
        		#print ("El response code es: "+ str(jdata['response_code']))
        		try:
        			time.sleep(2)
        			#vt.updateReport(md5)
        			jdata = vt.returnjdata(md5)
        			if(str(jdata['response_code']) == "-2"):
        				print("Aun esta sin procesar...")
        				#var1.set("Consultando en la BD de VirusTotal...")
        			if (str(jdata['response_code']) == "1"):
        				logging.info('Analisis Fichero: Se ha obtenido el resultado del fichero')
        				print("RESULTADO OBTENIDO!!!")
        				vt.muestraInforme(jdata)
        		except ValueError as error1:
        			print ("Se esta procesando...")
        			#var1.set("En unos momentos tendra el resultado...")
        			time.sleep(2)
	                #vt.updateReport(md5)



    # FUNCION QUE MUESTRA EL INFORME DEL FICHERO/MD5 A ANALIZAR
    def muestraInforme(self,jdata):
        vt = apiVirusTotal()
        result = ""
        #result = result + direccionFichero.get() + "\n\n"
        
        if (str(jdata['positives']) == "0"):
            #print ("No se ha encontrado ninguna amenaza en el archivo")
            result = result + "\n No se ha encontrado ninguna amenaza en el archivo"
            logging.info('Analisis Fichero/MD5: No se ha encontrado ninguna amenaza en el fichero')
            #var1.set("\n No se ha encontrado ninguna amenaza en el archivo")
        else:
            print("ALERTA","El fichero ha sido localizado como infectado por " +str(jdata['positives'])+ " antivirus" )
            logging.info('Analisis Fichero/MD5: El fichero ha sido localizado como infectado por ' +str(jdata['positives'])+ 'antivirus' )
            result = result + '\n Fichero localizado como infectado en: '+str(jdata['positives'])+ ' antivirus \n \n' 
            #var1.set("Fichero localizado como infectado en: "+str(jdata['positives'])+ " antivirus")
            #print ("\n\tResults for MD5: ",jdata['md5'],"\n\n\tDetected by: ",jdata['positives'],'/',jdata['total'],'\n')

            #El primer valor obtenido del jdata dentro del apartado scans, es el nombre del antivirus que ha analizado el fichero, de modo que debemos recoger este 
            #nombre como si fuera una parte del json cuando hagamos la consulta
            for scan in jdata['scans']:
                #CON ESTO OBTENGO EL NOMBRE DE TODOS LOS ANTIVIRUS
                #print (scan)
                if(jdata['scans'][scan]['detected']):
                    result = result + 'Localizado como malicioso por ' + scan + ' e identificado como ' + jdata['scans'][scan]['result'] + '\n'
                    #print ("Localizado como malicioso por " + scan + " e identificado como " + jdata['scans'][scan]['result'])
                
            
        result = result + '\n \nFecha análisis en VirusTotal: ' + jdata['scan_date'] 
        print(result)
        
        #REGISTRAR EN LA BASE DE DATOS LOCAL
        cursor.execute("insert or ignore into amenazas (md5, texto) values (?, ?)",(jdata['md5'], result))
        bd.commit() #Guardamos los cambios 
		
		

        #print(confirm)
        confirm = input("Desea exportar a PDF? (Y/N)")
        if confirm =="Y":
            tipo = "fichero"	
            vt.exportPDF(result,tipo)
            print("El informe ha sido guardado en la carpeta /reports/ficheros del proyecto")
        


    ##########################
    #     FUNCIONES MD5      #
    ##########################

    
    #ESTA FUNCION LA UTILIZAMOS EN CASO DE QUE QUERAMOS COMPROBAR UNICAMENTE EL MD5, NO EL ARCHIVO
    def md5Report(self,md5):
        
        #label2.pack_forget()
        #Llamamos a la clase para tener acceso a todas las funciones
        vt = apiVirusTotal()
        jdata = vt.returnjdata(md5)

        if jdata['response_code'] == 0:
            print (md5 + "-- No se ha encontrado en virustotal")
            logging.info('Analisis MD5: El MD5 '+ md5 + 'no ha sido localizado en VirusTotal')
        else:
            vt.muestraInforme(jdata)

    ##########################
    #     FUNCIONES URL      #
    ##########################

    # BUSQUEDA Y ACTUALIZACION URL VIRUS TOTAL

    def scanURL(self,urlBusqueda):
        vt = apiVirusTotal()
        # Las web pueden cambiar continuamente ya sea para mejoras o porque haya sido atacada por alguien, de modo que debemos escanear la URL en Virus Total
        # para que sea analizada de nuevo y obtener un informe actualizado (la web puede que no haya sido nunca analizada, o si lo ha sido, podría ser hace tiempo)

        url = self.base + "url/scan"
        param = {'apikey': self.api, 'url': urlBusqueda}
        response = requests.post(url,data=param)
        jdata = response.json()

        fecha_analisis = jdata['scan_date']

        print ("La fecha de analisis es: " + fecha_analisis)

        vt.reportWeb(urlBusqueda,fecha_analisis)

        #print (jdata)
        #vt.reportWeb(urlBusqueda)

    # REPORT URL

    def reportWeb(self, urlBusqueda, fecha_analisis):
        avt = apiVirusTotal()

        result = ""
        #Vaciamos el valor en caso de que hubieramos abierto antes analizar fichero

        url = self.base + "url/report"
        param = {'apikey': self.api, 'resource': urlBusqueda}
        response = requests.post(url,params=param)
        jdata = response.json()

        result = "\n El sitio web analizado es:  " + urlBusqueda + "\n\n"
        logging.info('Analisis URL: Se ha analizado la URL: '+ urlBusqueda)
        try:
            # Como acabamos de analizar la web, es probable que aún no tengamos el informe más reciente de su análisis, esto podemos comprobarlo a partir del resultado
            # de la fecha del análisis, llamado jdata['scan_date'], de modo que si esta fecha no coincide con la del escaneo que hemos realizado anteriormente
            # significará que aún no ha sido actualizada la BD de Virus Total, de modo que realizaremos de nuevo la llamada a la función hasta que ambas fechas coincidan.
            if(jdata['scan_date'] != fecha_analisis):
                #print ("La fecha del report obtenido es "+ jdata['scan_date'] + " y la fecha del ultimo analisis es " + fecha_analisis)
                print ("Actualizando el informe de este dominio...")
                time.sleep(2)
                avt.reportWeb(urlBusqueda,fecha_analisis)
            # En caso contrario, la base de datos sobre este dominio estará actualizada a la ultima comprobación    
            else:
                #print ("Coinciden las fechas")
                if (jdata['positives'] == 0):
                    print ("No se ha encontrado ninguna amenaza en la URL")
                    logging.info('Analisis URL: No se han encontrado amenazas en la URL')
                    result = result + "No se ha encontrado ninguna amenaza en la URL \n\n"
                else:
                    result = result + "PELIGRO! Se han encontrado "+ str(jdata['positives']) + " amenazas en distintos antivirus \n\n"
                    logging.info('Analisis URL: Se han contrado '+ str(jdata['positives']) + 'amenazas en diferentes antivirus')
                    print ("PELIGRO! Se han encontrado "+ str(jdata['positives']) + " amenazas en distintos antivirus")
                    for scan in jdata['scans']:
                        # Buscamos los scaners que han detectado el url como infectado y mostramos el contenido de su resultado
                        if (jdata['scans'][scan]['detected']):
                            result = result + 'Localizado como malicioso por ' + scan + ' e identificado como ' + jdata['scans'][scan]['result'] + '\n'

                result = result + "\n Fecha del análisis: "+ jdata['scan_date'] + "\n"
                print(result)
                confirm = input("Desea exportar a PDF? (Y/N)")
                if confirm == "Y":
                    tipo = "url"
                    avt.exportPDF(result,tipo)
                    print("El informe ha sido guardado en la carpeta /reports/urls del proyecto")
                else:
                    print ("No se ha exportado el informe")
        except KeyError as k:
            print("Aun no ha sido analizada nunca")
            time.sleep(2)
            avt.reportWeb(urlBusqueda,fecha_analisis)

        
        #print (jdata)

    def informationURL(self):
        logging.info('Se ha inicializado la opcion WHOIS URL')
        url = input("Introduzca la URL a analizar:")
        res = ""
        if str(url) != "None":
            if url == "":
                res = res + "Has introducido una url vacia"
                logging.info('WHOIS URL: Se ha introducido una URL vacía')
                print ("Has introducido una url vacia")
            else:
                # Para calcular la direccion IP de la URL introducida utilizamos la funcion socket.gethostbyname()
                #print (socket.gethostbyname(url))

                # Debemos controlar la excepción de que el usuario introduzca una URL errónea de modo que la aplicación devolvería error
                # (Si introduce una dirección IP no hay problema ya que la resuelve como ella misma)
                try:
                    ip = socket.gethostbyname(url)
                    #print(ip)
                    dirIP = IPWhois(ip)
                    #IMPORTANTE: CON LA VERSION QUE TIENE POR DEFECTO DABA WARNINGS, SIN EMBARGO HE INSTALADO LA SIGUIENTE VERSION CON EL SIGUIENTE COMANDO:
                    # py -m pip install ipwhois==0.10.3
                    logging.info('Se ha analizado la dirección: '+ url + ' con direccion IP: '+ ip)
                    result = dirIP.lookup_rws()
                    res = res + "\nINFORMACIÓN SOBRE EL DOMINIO: " + url
                    res = res + "\n\nASN: "+ result['asn']
                    res = res + "\nASN_CIDR: " + result['asn_cidr']
                    res = res + "\nASN_COUNTRY_CODE: " + result['asn_country_code']
                    res = res + "\nASN_DATE: " + result['asn_date']
                    res = res + "\nASN_REGISTRY: " + result['asn_registry']

                    res = res + "\n\nAbuse emails: " + str(result['nets'][0]['abuse_emails'])
                    res = res + "\nAddress: " + str(result['nets'][0]['address'])
                    res = res + "\nCidr: " + str(result['nets'][0]['cidr'])
                    res = res + "\nCity: " + str(result['nets'][0]['city'])
                    res = res + "\nCountry: " + str(result['nets'][0]['country'])
                    res = res + "\nCreated: " + str(result['nets'][0]['created'])
                    res = res + "\nDescription: " + str(result['nets'][0]['description'])
                    res = res + "\nMisc Emails: " + str(result['nets'][0]['misc_emails'])
                    res = res + "\nName: " + str(result['nets'][0]['name'])
                    res = res + "\nPostal Code: " + str(result['nets'][0]['postal_code'])
                    res = res + "\nState: " + str(result['nets'][0]['state'])
                    res = res + "\nTech emails: " + str(result['nets'][0]['tech_emails'])
                    res = res + "\nUpdated: " + str(result['nets'][0]['updated'])

                    print(res)


                except ValueError:
                    messagebox.showerror("ERROR","La URL: " + url +" no es correcta")



#####################
#CLASE OBTENCION MD5#
#####################

class fichero():
    def md5sum(self,filename):
        fh = open(filename, 'rb')
        m = hashlib.md5()
        while True:
            data = fh.read(8192)
            if not data:
                break
            m.update(data)
        return m.hexdigest()

    def checkMD5(self,checkval):
        fc = fichero()
        if re.match(r"([a-fA-F\d]{32})", checkval) == None:
            md5 = fc.md5sum(checkval)
            return md5.upper()
        else:
            return checkval.upper()



####################
#FUNCIONES DEL MENÚ#
####################
def main():

        # DEFINIMOS LAS CLASES
    ms = mensajes()
    avt = apiVirusTotal()
    fc = fichero()
    ms.inicio()
    ms.menu()


    opcionMenu = ""
    while opcionMenu != "9":
        opcionMenu = input("inserta un numero valor >> ")   
        if opcionMenu=="1":
            print ("")
            md5 = input("Introduzca el MD5 >> ")
            if str(md5) != "None":
                if md5 == "":
                    print ("Has introducido un MD5 vacío")
                    input("pulsa una tecla para continuar")
                    os.system ("cls")
                    ms.menu()
                    
                else:
                    avt.md5Report(md5)
                    input("pulsa una tecla para continuar1")
                    os.system ("cls")
                    ms.menu()

        elif opcionMenu=="2":
            direccionURL = input("Introduzca la URL >> ")
            if str(direccionURL) != "None":
                if direccionURL == "":
                    logging.info('Analisis URL: Se ha introducido una URL vacia')
                    print ("Has introducido una url vacia")
                    input("pulsa una tecla para continuar")
                    os.system ("cls")
                    ms.menu()
                else:
                    avt.scanURL(direccionURL)
                    input("pulsa una tecla para continuar")
                    os.system ("cls")
                    ms.menu()
                    
        elif opcionMenu=="3":
            avt.informationURL()
            input("pulsa una tecla para continuar")
            os.system ("cls")
            ms.menu()

        elif opcionMenu=="4":
            print ("")
            rutaFichero = input("Introduzca la ruta del fichero>> ")
            md5 = fc.checkMD5(rutaFichero)
            avt.getReport(md5,rutaFichero)
            input("pulsa una tecla para continuar")
            os.system ("cls")
            ms.menu()
        elif opcionMenu=="9":
            print ("")
            input("CERRANDO LA APLICACIÓN...\npulsa INTRO para finalizar")
        else:
            print ("")
            input("No has pulsado ninguna opción correcta...\npulsa INTRO para continuar")


#Llamamos al la funcion main
main()
