import nfc4py
import os
import pickle
import random
import time
import sys
import logging
from logging import handlers


PIN = 18
logger = logging.getLogger()
file_handler = handlers.RotatingFileHandler(filename='access.log', maxBytes=10000000, backupCount=1, encoding='utf8')
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
file_handler.setFormatter(formatter)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
# 文件日志
logger.addHandler(file_handler)
logger.addHandler(console_handler)
# 指定日志的最低输出级别
logger.setLevel(logging.INFO)


def _open(uid):
    import RPi.GPIO as GPIO
    logger.info(f'正在开门({uid})')
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(PIN, GPIO.OUT)
    GPIO.output(PIN, GPIO.HIGH)
    time.sleep(3)
    GPIO.output(PIN, GPIO.LOW)
    GPIO.cleanup()


def main():
    nfc4py.init_nfc()
    while True:
        try:
            time.sleep(2)
            uid = nfc4py.wait_tag()
            if not uid:
                raise ValueError('tag not found')
            uid_str = uid.hex()
            logger.info(f'Detect UID {uid_str}')
            card_dir = os.path.join('cards', uid_str)
            if not os.path.exists(card_dir):
                raise ValueError(f'UID {uid_str} not found in system')
            with open(os.path.join(card_dir, 'data.pkl'), 'rb') as f:
                data = pickle.load(f)
            sector = random.randint(1, len(data) - 1)
            logger.info(f'Reading sector {sector} with key {data[sector][1].hex(), data[sector][2].hex()}')
            sector_data = nfc4py.read_sector(sector, data[sector][1], data[sector][2], 1)
            if b''.join(data[sector][0]) == sector_data:
                logger.info(f'Card {uid_str} is valid')
                _open(uid_str)
            else:
                logger.warning(f'Card {uid_str} is bad')
        except KeyboardInterrupt:
            logger.info('Exiting ...')
            nfc4py.close()
            return
        except Exception as e:
            logger.warning(e)


if __name__ == '__main__':
    main()
