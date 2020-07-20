#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

import sys
import time
# sys.path.insert(0, './protobuf')

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

from . import wam_log as log
from . import wam_debug as DEBUG
from . import wam_encoder as encoder
from . import wam_error as error

from .protobuf import general_pb2

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

def _generate_error_response(err_code, err_msg):
	response = '{"response" : { "header" : { "version" : "1.0", "response_from" : "wam", "status" : "error" }, "body" : { "error" : { "code" : "' + encoder.json_get_error_code(err_code) + '", "message" : "' + err_msg + '" } } } }'
	return response

def send_and_receive(request, connector):
	log.i("REQUEST is : ")
	log.i(request)

	try:
		#
		_encoder = encoder.Encoder()
		encoded_list = _encoder.encode(request)

		#
		encoded_response_list = []
		for encoded in encoded_list:
			log.d("send : " + str(encoded))
			is_again = True
			while is_again == True:
				##
				#
				start_time = time.time()

				connector.send(encoded)
				encoded_response = connector.receive()

				log.d("process time : %s sec" % (time.time() - start_time))

				##
				#
				log.d("receive : " + str(encoded_response))
				encoded_response_list.append(encoded_response)
				is_again = encoder.get_has_more(encoded_response)
				log.d("is_again : " + str(is_again))

			is_error = encoder.get_is_error(encoded_response)
			if is_error == True:
				break;

		#
		response = _encoder.decode(encoded_response_list)

	except error.WamException as e:
		log.e("WamExcecption : " + str(e.get_code()) + ", " + e.get_msg())
		# response = _generate_error_response(e.get_code(), e.get_msg())
		raise e		
	except (Exception, BaseException) as e:
		log.e("EXCEPTION : " + str(e))
		# response = _generate_error_response(general_pb2.unknown, str(e))
		raise e

	finally:
		log.d("RESPONSE is : ")
		log.d(response)
		return response

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

if __name__ == '__main__':
    print("SAMPLE TEST STARTED")
    log.set(LogLevel.verbose.value)
    request = '{"request" : { "header" : { "version" : "1.0", "request_to" : "device" }, "body" : { "command" : "get_info", "parameter" : ""} }}'
    response = send_and_receive(request)
    print("SAMPLE TEST END")
# END TEST MAIN CODE

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

