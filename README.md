# Чат-приложение с аутентификацией через Steam

Этот проект представляет собой чат-приложение с реальным временем работы, созданное с использованием Node.js, Express, WebSocket, Passport.js и MySQL. Приложение позволяет пользователям вести беседы в реальном времени, а также интегрирует аутентификацию через Steam для идентификации пользователей.

## Особенности

- **Чат в реальном времени:** Пользователи могут отправлять и получать сообщения в реальном времени в чат-комнате.
- **Аутентификация через Steam:** Безопасный вход в систему с использованием аутентификации Steam для идентификации пользователей.
- **База данных MySQL:** Сообщения сохраняются в базе данных MySQL для исторической справки.
- **Бэкенд на Express.js:** Сервер работает на Express.js, обеспечивая надежность и масштабируемость.
- **WebSocket:** Использование WebSocket для реального времени связи между сервером и клиентами.
- **Интеграция JWT:** Использование JSON Web Tokens (JWT) для безопасной аутентификации и авторизации.
- **Список онлайн пользователей:** Пользователи могут проверять кто на данный момент сидит в чате помимо себя, список пользователей работает в реальном времени и обновляется даже когда пользователи закрывают сайт или браузер


## Начало работы

1. **Клонировать репозиторий:**
```bash
git clone https://github.com/uximy/chat-application.git
```
2. **Установить зависимости:**
```bash
  cd chat-application
  npm install
```
3. **Настроить ключ API Steam:**
Получите ключ API Steam и обновите файл конфигурации (config.json) этим ключом.

4. **Настроить базу данных MySQL:**
Обновите данные для подключения к MySQL в коде (app.js) в соответствии с вашей настройкой базы данных.

5. **Сгенерировать SSL-сертификаты:*
Сгенерируйте SSL-сертификаты (sdk.key, sdk.cert) для безопасного HTTPS-соединения.

6. **Запустить приложение:**
```bash
  npm start
```
7. **Перейти по адресу `https://localhost:3000`:**
Откройте веб-браузер и перейдите по адресу `https://localhost:3000`, чтобы получить доступ к чат-приложению.

## Участие в разработке
Любые вклады приветствуются! Не стесняйтесь открывать проблемы, отправлять запросы на внесение изменений или предлагать идеи для улучшения

## Лицензия
Этот проект лицензирован в соответствии с условиями MIT License - см. файл [LICENSE](LICENSE) для подробностей.
