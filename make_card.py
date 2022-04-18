import uuid
import os
import pickle
import shutil


CARD_DIR = 'cards'


def new_keys():
	buf = uuid.uuid4().bytes
	key_a, key_b = buf[:6], buf[-6:]
	return key_a, key_b


def new_sector(i):
	if i == 0:
		uid = uuid.uuid4().bytes[:4]
		bt_BCC = uid[1].to_bytes(1, 'big')
		sak = b'\x08'
		atqa = b'\x04\x00'
		manufacturer = uuid.uuid4().bytes[:8]
		data = [uid + bt_BCC + sak + atqa + manufacturer]
		data.extend([bytes(16) for i in range(2)])
		key_a, key_b = new_keys()
	else:
		data = [uuid.uuid4().bytes for j in range(3)]
		key_a, key_b = new_keys()
	
	data.append(key_a + b'\xff\x07\x80\x69' + key_b)
	return data, key_a, key_b


def new_card():
	data = [new_sector(i) for i in range(1, 16)]
	return data


def main():
	os.system('nfc-mfclassic r a tmp.mfd')
	assert os.path.exists('tmp.mfd')
	with open('tmp.mfd', 'rb') as f:
		sector0 = f.read(16 * 4)
		sector0 = [sector0[i:(i + 16)] for i in range(0, 16 * 4, 16)]
	uid = sector0[0][:4]
	data = new_card()
	data.insert(0, (sector0, sector0[-1][:6], sector0[-1][-6:]))
	card_path = os.path.join(CARD_DIR, uid.hex())
	os.makedirs(card_path, exist_ok=True)
	with open(os.path.join(card_path, 'data.pkl'), 'wb') as f:
		pickle.dump(data, f, pickle.HIGHEST_PROTOCOL)
	with open(os.path.join(card_path, 'raw.mfd'), 'wb') as f:
		f.write(b''.join([b''.join(sector) for sector, key_a, key_b in data]))
	original_card = os.path.join(card_path, 'original.mfd')
	new_card_path = os.path.join(card_path, 'raw.mfd')
	shutil.copyfile('tmp.mfd', original_card)
	os.remove('tmp.mfd')
	os.system(f'nfc-mfclassic w a {new_card_path} {original_card}')


if __name__ == '__main__':
	main()
