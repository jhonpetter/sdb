//SAKEP Message Format 
#define SAKEP_AKE_MSG_START_INDEX														0
#define SAKEP_AKE_MSG_VERSION_LEN														1
#define SAKEP_AKE_MSG_DATATYPE_LEN													1
#define SAKEP_AKE_MSG_TIMESTAMP_LEN													4
#define SAKEP_AKE_MSG_PAYLOAD_ALG_LEN												1
#define SAKEP_AKE_MSG_PAYLOAD_LENGTH_LEN										4
#define SAKEP_AKE_MSG_USERID_LENGTH_LEN											4
#define SAKEP_AKE_MSG_PAYLOAD_EN_DATA_LEN										128
#define SAKEP_AKE_MSG_INITIAL_SETUP_DATA_LEN								128	
#define SAKEP_AKE_MSG_PAYLOAD_HASH_DATA_LEN									20
#define SAKEP_AKE_MSG_ACK_SERVER_PAYLOAD_LEN								20
#define SAKEP_AKE_MSG_SK_PAYLOAD_HASH_DATA_LEN							20
#define SAKEP_AKE_MSG_INTEGRYITY_TYPE_LEN										1
#define SAKEP_AKE_MSG_INTEGRYITY_LENGTH_LEN									4
#define SAKEP_AKE_MSG_INTEGRYITY_MAC_LENGTH_LEN							20
#define SAKEP_AKE_MSG_TOT_HASH_DATA_LEN											20
#define SAKEP_AKE_MSG_CLIENTHELLO_FIXED_LEN									168
#define SAKEP_AKE_MSG_SERVERHELLO_FIXED_LEN									148
#define SAKEP_AKE_MSG_INITALSETUP_FIXED_LEN									148
#define SAKEP_AKE_MSG_RECORD_FIXED_LEN 											36
#define SAKEP_AKE_MSG_ACK_FIXED_LEN													20
#define SAKEP_MAC_KEY_SIZE																	20
#define SAKEP_AKE_USERID_LEN																32
#define SAKEP_SHARED_KEY_SIZE																16
#define SAKEP_SK_PRIME_KEY_SIZE															20
#define SAKEP_PREVIOS_MESSAGE_HASH_SIZE											20
#define SAKEP_SHA1_HASH_SIZE																20
#define SAKEP_DLBP_PAK_PARMETER_SIZE												128
#define SAKEP_DLBP_PAK_ORDER_PARMETER_SIZE									20
#define SAKEP_SHA1_DIGEST_LENGTH														20
#define SPC_SERVERACK_SUCCESS																0//ack payload message
#define SAKEP_IV_SIZE																				16
#define SAKEP_AES_ECB_ADDED_PADDING_SIZE										16
#define SPC_WB_BLOCK_SIZE																		16
#define SAKEP_GXY_KEY_SIZE																	16

//PBKEF 
#define SAKEP_PBKDF_DK_SIZE																	16
#define SAKEP_MFEK_KEY_SIZE																	16
#define SAKEP_AUTH_KEY_SIZE																	16
#define SAKEP_PBKDF_COUNT																		100

//ERROR message
#define SPC_SUCCESS														0

#define SAKEP_FILE_ENDECRYPTION_FILE_OPEN_ERROR						-161
#define SAKEP_FILE_ENDECRYPTION_FILE_SEEK_ERROR						-162
#define SAKEP_FILE_ENDECRYPTION_FILE_READ_WRITE_ERROR			-163
#define SAKEP_FILE_ENDECRYPTION_FILE_ENDECRYPTED_ERROR		-164
#define SAKEP_ENCRYPTION_DECRYPTION_ERROR									-165

#define SAKEP_MEMROY_ALLOCATE_ERROR												-180
#define SAKEP_INPUT_INVALID_ERROR													-181
#define SAKEP_MESSAGE_ERROR																-182
#define SAKEP_NULL_POINT_ERROR														-183
#define SAKEP_UNEXPECTED_MESSAGE_ERROR										-184 
#define SAKEP_CREATE_PIPRIME_ERROR												-185
#define SAKEP_GETGX_SETBSPARAM_ERROR											-186
#define SAKEP_GETGX_GENEARTORBSPRIVATE_ERROR							-187
#define SAKEP_GETGX_ERROR																	-188
#define SAKEP_GETGYWC_SETBSPARAM_ERROR										-189
#define SAKEP_GETGYWC_GENEARTORBSPUBLIC_ERROR							-190
#define SAKEP_INVAILD_STATE_ERROR													-191
#define SAKEP_MESSAGE_GENERATE_FAIL												-200

#define	SAKEP_VALIDATION_FAILED															-201
#define	SAKEP_INVALID_PARAMETER															-202
#define	SAKEP_MAC_VALIDATION_FAILED													-203 
#define	SAKEP_INVALID_RECOVERY_DATA_LENGTH									-204
#define SAKEP_IV_CREATE_FAIL																-205
#define SAKEP_SDWAP_FAILED																	-206
#define SAKEP_SWAP_FAILED																		-207
#define SAKEP_KEY_CREATE_FAIL																-208
#define SAKEP_GD_DECRYPITON_FAIL														-209
#define SAKEP_PASSWORD_TRANSFORM_FAIL												-210
#define SAKEP_INVALID_TRANSFORMED_PADDING										-211
#define SAKEP_ENCRYPT_GX_FAIL													-212
#define SAKEP_DECRYPT_GX_FAIL													-213
#define SAKEP_DECRYPT_GY_FAIL													-214
#define SAKEP_ENCRYPT_GY_FAIL													-215
#define SAKEP_USERID_INVAILD													-216    // USERID IS NOT SAME (Peer UserID and My UserID)
#define SAKEP_ERROR																					-1
#define SAKEP_SUCCESS																				0
#define	SAKEP_VALIDATION_SUCCESS														0


//error Type 
typedef enum {
	UNSPPORTED_VERSION_ERROR=0x81,
	INVALID_RECORD_PROTOCOL_ERROR,
	INTEGRITY_ERROR,
	INTEGRITY_LENGTH_ERROR,
	UNEXPECTED_MESSAGE_ERROR,
	INVALID_CLIENT_HELLO_ERROR,
	INVALID_SERVER_HELLO_ERROR,
	INVALID_SERVER_ACK_ERROR,
	INVALID_CLIENT_ACK_ERROR,
	INVALID_INITIALSETUP_ERROR,
	INVALID_TOKEN_REQ_ERROR,
	INVALID_TOKEN_VALIDATION_REQ_ERROR,
	INVALID_CLIENT_ACK_PAYLOAD_ERROR,
	RECORD_ENCRYPTED_ERROR,
	RECORD_DECRYPTED_ERROR,
	RECORD_INVALID_INTEGRITY_ERROR,
	FILE_ENCRYPTED_ERROR,
	FILE_DECRYPTED_ERROR,
	UNSPPORTED_ENDECRYPTION_MODE,
	INVALIED_PARAMETER_ERROR,
	INVALIED_PAYLOAD_LEN_ERROR,
	LOGIN_COUNT_LIMITED_ERROR,
	UNKNOWN_ERROR,
	GD_DECRYPTION_ERROR,
	PASSWORD_TRANSFORM_FAIL,
	SUCCESS=0x00
}ErrorType;

typedef enum {	
	STATE_IDLE,
	STATE_WAIT_INITALSETUP,				
	STATE_WAIT_CLIENTHELLO,
	STATE_WAIT_SERVERHELLO,
	STATE_WAIT_SERVERACKHELLO,
	STATE_WAIT_CLIENTACKHELLO,
	STATE_AKE_CANCEL,
	STATE_ERROR,
	STATE_COMPLETED
	
}AkeState;

typedef struct
{
	unsigned char pSharedkey[SAKEP_SHARED_KEY_SIZE];
	unsigned char	pSKPrime[SAKEP_SK_PRIME_KEY_SIZE];
	unsigned char	pPreHashMsg[SAKEP_SHA1_HASH_SIZE];	
	AkeState		eState;
	ErrorType		eErrorType;
//	unsigned int	nSeqNum;
//	unsigned char  pCurrentID[SAKEP_AKE_USERID_LEN];//ÇöÀçÀÇ ID 
}Handle_CTX;

typedef enum 
{
	SERVER_MODE,
	CLIENT_MODE
}ModeType;



#define ID_MAX_LEN			256
#define PWD_MAX_LEN			32
#define TOT_USERCOUNT_LEN		4
#define ID_PWD_FIELD_LEN	4
#define USERCOUNT_MAX		8
#define SPC_LOGIN_LIMITED_COUNT 5



#define SPC_ENCRYPT_FORMAT_MFEK1_LEN					4
#define SPC_ENCRYPT_FORMAT_USERID_LEN					4
#define SPC_ENCRYPT_FORMAT_FILE_LEN						4
#define SPC_ENCRYPT_FORMAT_FEK1_LEN						4
#define SPC_ENCRYPT_FORMAT_FEK1_LEN						4
#define SPC_ENCRYPT_FORMAT_USERMAC_LENGTH_LEN			4
#define SPC_ENCRYPT_FORMAT_USERMAC_LEN					20



//Error type
#define SPC_SUCCESS							0
#define SPC_FAIL							-1
#define INPUT_ERROR					-200


typedef struct
{
	//unsigned char	pUserID[ID_MAX_LEN];
	unsigned char	*pUserID;
	unsigned int   nUserIDLen;
	unsigned int	LoginTryCount;
	Handle_CTX		ctx;
}SPCHandle_CTX;




