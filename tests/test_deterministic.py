import unittest
from pathlib import Path
from app.parser import parse

CONFIG = Path(__file__).resolve().parent.parent / 'config'


class DeterministicTests(unittest.TestCase):
    def test_group(self):
        text = ('зарегистрировано добавление учётной записи в локальную '
                'привилегированную группу Администраторы пользователем PC01\\Администратор.\n'
                'Добавленная учетная запись: corp\\ivanov\n'
                'Хост, на котором зарегистрировано событие: 10.10.10.20 - PC01.corp.com')
        result, _ = parse(text, CONFIG)
        self.assertEqual(result['data']['username'], ['ivanov'])
        self.assertEqual(result['data']['dst.hostname'], ['pc01'])
        self.assertEqual(result['data']['src.username'], ['PC01\\Администратор'])
        self.assertEqual(result['data']['dst.ip'], ['10.10.10.20'])

    def test_credential_manager(self):
        text = ('24 Nov 2026, 11:12:48 UTC на хосте 10.10.10.20 - '
                'vnp0142.corp.com обнаружено использование встроенных утилит '
                'Windows для получения информации о хранящихся в Credential Manager учетных данных.\n'
                'Выполненная команда:\n'
                'rundll32.exe keymgr.dll,KRShowKeyMgr\n'
                'УЗ — инициатор активности: corp\\ivanov.\n'
                'Эта активность может указывать на легитимные действия.')
        result, _ = parse(text, CONFIG)
        self.assertEqual(result['data']['dst.hostname'], ['vnp0142'])
        self.assertEqual(result['data']['dst.ip'], ['10.10.10.20'])
        self.assertEqual(result['data']['username'], ['ivanov'])
        self.assertEqual(result['category'], 'Событие безопасности')

    def test_glued(self):
        result, _ = parse('УЗ-инициатор активности: rootЦелевой хост:10.1.2.3server.corp.com', CONFIG)
        self.assertEqual(result['data']['src.username'], ['root'])
        self.assertEqual(result['data']['username'], [])
        self.assertEqual(result['data']['dst.hostname'], ['server'])
        self.assertEqual(result['data']['dst.ip'], ['10.1.2.3'])

    def test_scan(self):
        result, _ = parse('зарегистрировано сканирование внутренней сети с хоста10.1.2.3\n'
                          'Внутреннее сканирование сети может быть обусловлено заражением ВПО', CONFIG)
        self.assertEqual(result['category'], 'Сетевая атака')
        self.assertEqual(result['data']['src.ip'], ['10.1.2.3'])

    def test_malware(self):
        result, _ = parse('Категория угрозы: HEUR:Backdoor.MSIL.Remcos.gen\n'
                          'Действие АВПО над объектом: Обнаружено', CONFIG)
        self.assertEqual(result['category'], 'Вредоносное программное обеспечение')


if __name__ == '__main__':
    unittest.main()
