#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <Python.h>
#include <string.h>
#include <ctype.h>

#include <nfc/nfc.h>

#include <mifare.h>
#include <nfc-utils.h>

static nfc_context *context;
static nfc_device *pnd;
static nfc_target nt;
static mifare_param mp;
static mifare_classic_tag mtKeys;
static mifare_classic_tag mtDump;
static bool bUseKeyA;
static bool bUseKeyFile;
static bool bForceKeyFile;
static bool bTolerateFailures;
static bool bFormatCard;
static bool magic2 = false;
static uint8_t uiBlocks;
static uint8_t keys[] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7,
  0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
  0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
  0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd,
  0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a,
  0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xab, 0xcd, 0xef, 0x12, 0x34, 0x56
};
static uint8_t default_key[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static uint8_t default_acl[] = {0xff, 0x07, 0x80, 0x69};

static const nfc_modulation nmMifare = {
  .nmt = NMT_ISO14443A,
  .nbr = NBR_106,
};

static size_t num_keys = sizeof(keys) / 6;

#define MAX_FRAME_LEN 264

static uint8_t abtRx[MAX_FRAME_LEN];
static int szRxBits;

uint8_t  abtHalt[4] = { 0x50, 0x00, 0x00, 0x00 };

// special unlock command
uint8_t  abtUnlock1[1] = { 0x40 };
uint8_t  abtUnlock2[1] = { 0x43 };

static  bool
transmit_bits(const uint8_t *pbtTx, const size_t szTxBits)
{
  // Show transmitted command
  printf("Sent bits:     ");
  print_hex_bits(pbtTx, szTxBits);
  // Transmit the bit frame command, we don't use the arbitrary parity feature
  if ((szRxBits = nfc_initiator_transceive_bits(pnd, pbtTx, szTxBits, NULL, abtRx, sizeof(abtRx), NULL)) < 0)
    return false;

  // Show received answer
  printf("Received bits: ");
  print_hex_bits(abtRx, szRxBits);
  // Succesful transfer
  return true;
}


static  bool
transmit_bytes(const uint8_t *pbtTx, const size_t szTx)
{
  // Show transmitted command
  printf("Sent bits:     ");
  print_hex(pbtTx, szTx);
  // Transmit the command bytes
  int res;
  if ((res = nfc_initiator_transceive_bytes(pnd, pbtTx, szTx, abtRx, sizeof(abtRx), 0)) < 0)
    return false;

  // Show received answer
  printf("Received bits: ");
  print_hex(abtRx, res);
  // Succesful transfer
  return true;
}

static void
print_success_or_failure(bool bFailure, uint32_t *uiBlockCounter)
{
  printf("%c", (bFailure) ? 'x' : '.');
  if (uiBlockCounter && !bFailure)
    *uiBlockCounter += 1;
}

static  bool
is_first_block(uint32_t uiBlock)
{
  // Test if we are in the small or big sectors
  if (uiBlock < 128)
    return ((uiBlock) % 4 == 0);
  else
    return ((uiBlock) % 16 == 0);
}

static  bool
is_trailer_block(uint32_t uiBlock)
{
  // Test if we are in the small or big sectors
  if (uiBlock < 128)
    return ((uiBlock + 1) % 4 == 0);
  else
    return ((uiBlock + 1) % 16 == 0);
}

static int32_t
get_sector_block(uint32_t sector, bool start)
{
	// Test if we are in the small or big sectors
	if (sector < 32)
		return start ? sector * 4 : sector * 4 + 3;
	else
		return start ? sector * 16 : sector * 16 + 15;
}

static  uint32_t
get_trailer_block(uint32_t uiFirstBlock)
{
  // Test if we are in the small or big sectors
  uint32_t trailer_block = 0;
  if (uiFirstBlock < 128) {
    trailer_block = uiFirstBlock + (3 - (uiFirstBlock % 4));
  } else {
    trailer_block = uiFirstBlock + (15 - (uiFirstBlock % 16));
  }
  return trailer_block;
}

static  bool
authenticate(uint32_t uiBlock, uint8_t* key_a, uint8_t* key_b, int use_key_a)
{
  mifare_cmd mc;
  uint32_t uiTrailerBlock;

  // Set the authentication information (uid)
  memcpy(mp.mpa.abtAuthUid, nt.nti.nai.abtUid + nt.nti.nai.szUidLen - 4, 4);

  // Should we use key A or B?
  mc = (use_key_a) ? MC_AUTH_A : MC_AUTH_B;

  // Locate the trailer (with the keys) used for this sector
  uiTrailerBlock = get_trailer_block(uiBlock);

  // Extract the right key from dump file
  if (use_key_a)
    memcpy(mp.mpa.abtKey, key_a, 6);
  else
    memcpy(mp.mpa.abtKey, key_b, 6);

  // Try to authenticate for the current sector
  if (nfc_initiator_mifare_cmd(pnd, mc, uiBlock, &mp))
    return true;
  return false;
}

static int
get_rats(void)
{
  int res;
  uint8_t  abtRats[2] = { 0xe0, 0x50};
  // Use raw send/receive methods
  if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, false) < 0) {
    nfc_perror(pnd, "nfc_configure");
    return -1;
  }
  res = nfc_initiator_transceive_bytes(pnd, abtRats, sizeof(abtRats), abtRx, sizeof(abtRx), 0);
  if (res > 0) {
    // ISO14443-4 card, turn RF field off/on to access ISO14443-3 again
    if (nfc_device_set_property_bool(pnd, NP_ACTIVATE_FIELD, false) < 0) {
      nfc_perror(pnd, "nfc_configure");
      return -1;
    }
    if (nfc_device_set_property_bool(pnd, NP_ACTIVATE_FIELD, true) < 0) {
      nfc_perror(pnd, "nfc_configure");
      return -1;
    }
  }
  // Reselect tag
  if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0) {
    printf("Error: tag disappeared\n");
    return 0;
  }
  return res;
}

static  bool
read_sector(int sector, uint8_t* key_a, uint8_t* key_b, int use_key_a, uint8_t** data, uint32_t* size)
{
  int32_t iBlock;
  bool    bFailure = false;
  uint32_t uiReadBlocks = 0;


  int32_t start_block = get_sector_block(sector, true);
  int32_t end_block = get_sector_block(sector, false);
  printf("Reading out %d blocks from %d to %d |", end_block - start_block + 1, start_block, end_block);
  // Read the card from end to begin
  for (iBlock = end_block; iBlock >= start_block; iBlock--) {
    // Authenticate everytime we reach a trailer block
    if (is_trailer_block(iBlock)) {
      if (bFailure) {
        // When a failure occured we need to redo the anti-collision
        if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0) {
          printf("!\nError: tag was removed\n");
          return false;
        }
        bFailure = false;
      }

      fflush(stdout);

      // Try to authenticate for the current sector
      if (!authenticate(iBlock, key_a, key_b, use_key_a)) {
        printf("!\nError: authentication failed for block 0x%02x\n", iBlock);
        return false;
      }
      // Try to read out the trailer
      if (nfc_initiator_mifare_cmd(pnd, MC_READ, iBlock, &mp)) {
          // Copy the keys over from our key dump and store the retrieved access bits
          memcpy(mtDump.amb[iBlock].mbt.abtKeyA, key_a, 6);
          memcpy(mtDump.amb[iBlock].mbt.abtAccessBits, mp.mpd.abtData + 6, 4);
          memcpy(mtDump.amb[iBlock].mbt.abtKeyB, key_b, 6);
      } else {
        printf("!\nfailed to read trailer block 0x%02x\n", iBlock);
        bFailure = true;
      }
    } else {
      // Make sure a earlier readout did not fail
      if (!bFailure) {
        // Try to read out the data block
        if (nfc_initiator_mifare_cmd(pnd, MC_READ, iBlock, &mp)) {
          memcpy(mtDump.amb[iBlock].mbd.abtData, mp.mpd.abtData, 16);
        } else {
          printf("!\nError: unable to read block 0x%02x\n", iBlock);
          bFailure = true;
        }
      }
    }
    // Show if the readout went well for each block
    print_success_or_failure(bFailure, &uiReadBlocks);
    if ((! bTolerateFailures) && bFailure)
      return false;
  }
  printf("|\n");
  printf("Done, %d of %d blocks read.\n", uiReadBlocks, uiBlocks + 1);
  fflush(stdout);
  *data = (uint8_t*)&mtDump.amb[start_block];
  *size = sizeof(mtDump.amb[iBlock].mbd.abtData) * (end_block - start_block + 1);
  return true;
}

int init_nfc()
{
	nfc_init(&context);
	if (context == NULL) {
		ERR("Unable to init libnfc (malloc)");
		return 1;
	}

	// Try to open the NFC reader
	pnd = nfc_open(context, NULL);
	if (pnd == NULL) {
		ERR("Error opening NFC reader");
		nfc_exit(context);
		return 1;
	}

	if (nfc_initiator_init(pnd) < 0) {
		nfc_perror(pnd, "nfc_initiator_init");
		nfc_close(pnd);
		nfc_exit(context);
		return 1;
	};

	// Let the reader only try once to find a tag
	if (nfc_device_set_property_bool(pnd, NP_INFINITE_SELECT, true) < 0) {
		nfc_perror(pnd, "nfc_device_set_property_bool");
		nfc_close(pnd);
		nfc_exit(context);
		return 1;
	}
	// Disable ISO14443-4 switching in order to read devices that emulate Mifare Classic with ISO14443-4 compliance.
	if (nfc_device_set_property_bool(pnd, NP_AUTO_ISO14443_4, false) < 0) {
		nfc_perror(pnd, "nfc_device_set_property_bool");
		nfc_close(pnd);
		nfc_exit(context);
		return 1;
	}

	printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));
	return 0;
}

void check_size()
{
	// Guessing size
	if ((nt.nti.nai.abtAtqa[1] & 0x02) == 0x02 || nt.nti.nai.btSak == 0x18)
		// 4K
		uiBlocks = 0xff;
	else if (nt.nti.nai.btSak == 0x09)
		// 320b
		uiBlocks = 0x13;
	else
		// 1K/2K, checked through RATS
		uiBlocks = 0x3f;
	// Testing RATS
	int res;
	if ((res = get_rats()) > 0) {
		if ((res >= 10) && (abtRx[5] == 0xc1) && (abtRx[6] == 0x05)
			&& (abtRx[7] == 0x2f) && (abtRx[8] == 0x2f)
			&& ((nt.nti.nai.abtAtqa[1] & 0x02) == 0x00)) {
			// MIFARE Plus 2K
			uiBlocks = 0x7f;
		}
		// Chinese magic emulation card, ATS=0978009102:dabc1910
		if ((res == 9) && (abtRx[5] == 0xda) && (abtRx[6] == 0xbc)
			&& (abtRx[7] == 0x19) && (abtRx[8] == 0x10)) {
			magic2 = true;
		}
	}
	printf("Guessing size: seems to be a %lu-byte card\n", (uiBlocks + 1) * sizeof(mifare_classic_block));
}

uint8_t* wait_tag()
{
	// Try to find a MIFARE Classic tag
	int tags;

	tags = nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt);
	if (tags <= 0) {
		printf("Error: no tag was found\n");
		return NULL;
	}
	// Test if we are dealing with a MIFARE compatible tag
	if ((nt.nti.nai.btSak & 0x08) == 0) {
		printf("Warning: tag is probably not a MFC!\n");
	}
	printf("Found MIFARE Classic card:\n");
	print_nfc_target(&nt, false);
	check_size();
	// Get the info from the current tag
	return nt.nti.nai.abtUid;
}

void clean()
{
	nfc_close(pnd);
	nfc_exit(context);
}

static PyObject* _py_init_nfc(PyObject* self)
{
	int ret = init_nfc();
	return Py_BuildValue("i", ret);
}

static PyObject* _py_close_nfc(PyObject* self)
{
	clean();
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject* _py_wait_tag(PyObject* self)
{
	char* t = (char*)wait_tag();
	if (t == NULL) {
		Py_INCREF(Py_None);
		return Py_None;
	}
	return PyBytes_FromStringAndSize(t, 4);
}

static PyObject* _py_read_sector(PyObject* self, PyObject* args)
{
	int sector, use_key_a;
	char* key_a, * key_b;
	int len_key_a, len_key_b;
	if (!(PyArg_ParseTuple(args, "is#s#i", &sector, &key_a, &len_key_a, &key_b, &len_key_b, &use_key_a))) {
		return NULL;
	}
	uint8_t* data;
	uint32_t size;
	bool ret = read_sector(sector, key_a, key_b, use_key_a, &data, &size);
	if (!ret) {
		Py_INCREF(Py_None);
		return Py_None;
	}
	return PyBytes_FromStringAndSize(data, size);
}

static PyMethodDef  methods[] = {
   {"init_nfc", _py_init_nfc, METH_NOARGS, "Init nfc"},
   {"wait_tag", _py_wait_tag, METH_NOARGS, "Wait for a tag"},
   {"read_sector", _py_read_sector, METH_VARARGS, "Read data from a sector"},
   {"close", _py_close_nfc, METH_NOARGS, "Close nfc"},
   {NULL, NULL}
};

static struct PyModuleDef nfc4pymodule = {
	PyModuleDef_HEAD_INIT,
	"nfc4py",   /* name of module */
	NULL, /* module documentation, may be NULL */
	-1,       /* size of per-interpreter state of the module,
				 or -1 if the module keeps state in global variables. */
	methods
};

PyMODINIT_FUNC PyInit_nfc4py() {
	return PyModule_Create(&nfc4pymodule);
}
