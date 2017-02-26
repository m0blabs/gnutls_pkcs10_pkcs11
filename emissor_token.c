/*
 * GERADOR DE CSR USANDO TOKENS - PKCS#10 + PKCS#11
 * Autor: Kingm0b_
 * 
 * Compila com:
 * $ gcc emissor_token.c -o emissor_token -lgnutls
 *
*/

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/pkcs11.h>

#include <gnutls/gnutls.h>
#include <gnutls/pkcs12.h>
#include <gnutls/pkcs11.h>
#include <gnutls/abstract.h>

#define MIN(x,y) ((x)<(y))?(x):(y)

static void erro(const char *, int);

int pin_callback(void *user, int attempt, const char *token_url, const char *token_label, unsigned int flags, char *pin, size_t pin_max) {
	char *senha = NULL;
	size_t len;

	//printf("Token '%s' com URL '%s' ", token_label, token_url);
	senha = getpass(" Insira o PIN: ");

	len = MIN(pin_max - 1, strlen(senha));
	memcpy(pin, senha, len);
	pin[len] = 0;

	return 0;
}

int token_callback(void *user, const char *label, const unsigned retry) {
	if (retry > 0) {
		fprintf(stderr, " Não foi possível encontrar o token %s\n", label);
		return -1;
	}

	printf(" Nenhum token foi encontrado!\n");
	return 0;
}

#define BITS	2048
#define LABEL	"M0bLabs-GNUTLS"

void gera_par(const char *url) {
	int ret;
	char raw_id[128];
	size_t raw_id_size;

	gnutls_datum_t cid = {NULL, 0};
	gnutls_datum_t publica_raw;

	raw_id_size = sizeof(raw_id);
	unsigned const char *id = "\xba\xba\xca\x00";

	/* A ideia seria criar o objeto no token com o CKA_ID: babaca */
	ret = gnutls_hex2bin(id, strlen(id), raw_id, &raw_id_size);
	if (ret < 0) {
		fprintf(stderr, " Erro na conversão do ID: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	cid.data = raw_id;
	cid.size = raw_id_size;

	/* Mas não funciona 
	printf(" CKA_ID: %d bytes", cid.size);
	for (int c = 0; c < cid.size; c++)
		printf("%02x:", cid.data[c]);
	printf("\b\n"); */

	printf(" Gerando par de chaves...\n");
	ret = gnutls_pkcs11_privkey_generate3(url, GNUTLS_PK_RSA, BITS, LABEL, &cid, GNUTLS_X509_FMT_PEM,
						&publica_raw, GNUTLS_KEY_DIGITAL_SIGNATURE, GNUTLS_PKCS11_OBJ_FLAG_LOGIN);

	if (ret == GNUTLS_E_SUCCESS) {
		fprintf(stdout, " Par de chaves gerado com sucesso!\n");
		return;
	}

	if (ret < 0)
		erro(" Falha na geração do par de chaves!", 0);
}

void descobre_url_do_token(char **url) {
	int ret;
	ret = gnutls_pkcs11_token_get_url(0, 0, url);

	if (ret < 0)
		erro("gnutls_pkcs11_token_get_url", ret);

}

void gera_csr(const char *privada_url, char *csr_pem, size_t csr_tam) {
	int ret;

	gnutls_x509_crq_t csr;
	gnutls_x509_crq_init(&csr);
	gnutls_x509_crq_set_version(csr, 0);

	gnutls_x509_crq_set_dn_by_oid(csr, GNUTLS_OID_X520_COUNTRY_NAME, 0, "BR", 2);
	gnutls_x509_crq_set_dn_by_oid(csr, GNUTLS_OID_X520_ORGANIZATION_NAME, 0, "ICP-Brasil", strlen("ICP-Brasil"));
	gnutls_x509_crq_set_dn_by_oid(csr, GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME, 0, "", strlen(""));
	gnutls_x509_crq_set_dn_by_oid(csr, GNUTLS_OID_X520_COMMON_NAME, 0, "EMISSAO", strlen("EMISSAO"));

	// Página 102
	gnutls_privkey_t chave_abstrata;
	gnutls_pubkey_t publica;
	gnutls_x509_privkey_t chave_x509;

	ret = gnutls_privkey_init(&chave_abstrata);
	if (ret < 0)
		erro("gnutls_privkey_init", ret);

	/* Vincula a estrutura da chave privada com sua respectiva URL */
	ret = gnutls_privkey_import_url(chave_abstrata, privada_url, 0);
	if (ret < 0)
		erro("gnutls_privkey_import_url", ret);

	ret = gnutls_pubkey_init(&publica);
	if (ret < 0)
		erro("gnutls_pubkey_init", ret);

	ret = gnutls_pubkey_import_privkey(publica, chave_abstrata, 0, 0);
	if (ret < 0)
		erro("gnutls_pubkey_import_privkey", ret);

	ret = gnutls_x509_crq_set_pubkey(csr, publica);
	if (ret < 0)
		erro("gnutls_x509_crq_set_pubkey", ret);

	ret = gnutls_x509_crq_privkey_sign(csr, chave_abstrata, GNUTLS_DIG_SHA256, 0);
	if (ret < 0)
		erro("gnutls_x509_crq_privkey_sign", ret);

	ret = gnutls_x509_crq_export(csr, GNUTLS_X509_FMT_PEM, csr_pem, &csr_tam);
	if (ret < 0)
		erro("gnutls_x509_crq_export", ret);

}

char * obtem_url_da_ultima_chave(const char *url_token) {
	int ret;
	unsigned int obj_qtd = 0;
	gnutls_pkcs11_obj_t *obj_list;

	ret = gnutls_pkcs11_obj_list_import_url4(&obj_list, &obj_qtd, url_token, GNUTLS_PKCS11_OBJ_ATTR_PRIVKEY | GNUTLS_PKCS11_OBJ_FLAG_LOGIN);

	if (ret < 0)
		erro("gnutls_pkcs11_obj_list_import_url4", ret);

	if (obj_qtd == 0)
		erro("Nenhum objeto encontrado!", 0);

	/* obj_list[obj_qtd - 1] == última posição do array, portanto, último objeto gerado */
	char *privada_url;
	ret = gnutls_pkcs11_obj_export_url(obj_list[obj_qtd - 1], 0, &privada_url);
	if (ret < 0)
		erro("gnutls_pkcs11_obj_export_url", ret);

	return privada_url;
}

static void erro(const char *msg, int id_erro) {
	fprintf(stderr, " ERRO: %s", msg);
	if (id_erro == 0)
		fprintf(stderr, "\n");
	else
		fprintf(stderr, ":%s\n", gnutls_strerror(id_erro));

	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
	int ret;

	char *url;
	char *url_pchave;

	char csr_pem[10 * 1024];
	size_t csr_tam = sizeof(csr_pem);

	if (argc < 2) {
		fprintf(stderr, "Use: %s <biblioteca>\n", argv[0]);
		return 1;
	}

	ret = gnutls_global_init();
	if (ret < 0)
		erro("gnutls_global_init", ret);

	ret = gnutls_pkcs11_init(GNUTLS_PKCS11_FLAG_MANUAL, NULL);

	if (ret == GNUTLS_E_SUCCESS) {
		ret = gnutls_pkcs11_add_provider(argv[1], NULL);

		if (ret < 0)
			erro("Falha no carregamento do provider", ret);
	}

	/* Registra os callbacks */
	gnutls_pkcs11_set_token_function(token_callback, NULL);
	gnutls_pkcs11_set_pin_function(pin_callback, NULL);

	/* Nomes de funções auto-explicativas */
	descobre_url_do_token(&url);
	gera_par(url);
	fprintf(stdout, " URL do Token: %s\n\n", url);

	url_pchave = obtem_url_da_ultima_chave(url);
	printf("\n Última chave privada: %s\n\n", url_pchave);

	gera_csr(url_pchave, csr_pem, csr_tam);

	//printf(" Tamanho chave pública: %u bytes\n", publica.size);
	//for (int c = 0; c < publica.size; c++) printf("%c", publica.data[c]);

	FILE * csr_arquivo = fopen("/tmp/CSR", "w");
	if (csr_arquivo == NULL)
		erro("fopen", 0);

	fprintf(csr_arquivo, "%s\n", csr_pem);
	csr_arquivo = stdout;
	fprintf(csr_arquivo, "\n CSR:\n\n %s\n", csr_pem);

	gnutls_free(url);
	gnutls_free(url_pchave);

	gnutls_pkcs11_deinit();
	gnutls_global_deinit();

	fclose(csr_arquivo);

	return 0;
}
