const https = require('https'),
      express = require('express'),
      app = express(),
      path = require('path'),
      fs = require('fs'),
      WebSocket = require('ws'),
      passport = require('passport'),
      session = require('express-session'),
      passportSteam = require('passport-steam'),
      SteamStrategy = passportSteam.Strategy,
      mysql = require("mysql2"),
      jwt = require('jsonwebtoken'),
      cookies = require("cookie-parser"),
      axios = require('axios');

const config = require('./config.json');

const pool = mysql.createPool({
    host: "localhost",
    user: config.database.username,
    database: config.database.baseName,
    password: config.database.password,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
}); 


const query = (sql, values) => {
    return new Promise((resolve, reject) => {
        pool.query(sql, values, (error, results, fields) => {
            if (error) reject(error);
            resolve(results);
        });
    });
};


// Required to get data from user for sessions
passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});

// Initiate Strategy
passport.use(new SteamStrategy({
    returnURL: `https://localhost:${config.port}/api/auth/steam/return`,
    realm: `https://${config.hostname}:${config.port}/`,
    apiKey: config.apiKey
    }, function (identifier, profile, done) {
        process.nextTick(function () {
            profile.identifier = identifier;

            // Создание JWT
            const user = { steamID: profile.id };
            const accessToken = jwt.sign(user.steamID, "secket_key");
            
            profile.accessToken = accessToken;

            return done(null, profile);
        });
    }
));

app.use(session({
    secret: 'Uximy90367849',
    saveUninitialized: false,
    resave: false,
    proxy: false,
    cookie: {
        maxAge: 3600000
    }
}));

app.use(passport.initialize());
app.use(passport.session());
app.set('view engine', "raz"); // установить движок шаблонов, установлен движок Razor
app.use(cookies());

const server = https.createServer({
    key: fs.readFileSync(__dirname+"/sert/sdk.key"), 
    cert: fs.readFileSync(__dirname+"/sert/sdk.cert"),
}, app);

const wss = new WebSocket.Server({ server });

const activeUsers = new Map();

wss.on('connection', function connection(ws) {
    ws.isClosing = false;

    ws.on('message', async function incoming(data) {
        // Преобразование данных из Buffer в объект JavaScript
        const b = Buffer.from(data);
        const obj = JSON.parse(b.toString());

        if (obj.action === 'logout') {
            ws.isClosing = true;
            ws.closingSteamID = obj.steamid;
        }

        //отправка сообщений на сторону клиента и в базу данных для сохранения истории сообщений
        if(obj.action == null) {
            // Сохраняем сообщение в базу данных один раз
            try {
                const sql = "INSERT INTO message_history (steamid, nickname, img, messages) VALUES(?, ?, ?, ?)";
                await query(sql, [obj.steamid, obj.nickname, obj.img, obj.messages]);
            } catch (error) {
                console.error("Ошибка при отправке данных в базу данных: ", error);
            }

            wss.clients.forEach(function each(client) {
                try {
                    if (client !== ws && client.readyState === WebSocket.OPEN) {
                        client.send(b.toString());
                    }
                } catch (error) {
                    console.error("Ошибка при отправке сообщения клиенту: ", error);
                }
            });
        }

        // Отправка текущего списка пользователей в сети новому клиенту
        if (obj.action != null && obj.action.steamid != null) {
            // Функция для обработки данных пользователя
            function handleUserAction() {
                let steamid = obj.action.steamid;
                const userInfo = {
                    "nickname": obj.action.nickname,
                    "img": obj.action.img
                };
            
                // Обновляем данные пользователя, если он уже существует,
                // или добавляем нового пользователя, если его нет в списке
                activeUsers.set(steamid, userInfo);
            }
            
            // Пример использования функции
            handleUserAction();
            broadcastActiveUsers(); // Отправляем обновленный список всем пользователям
        }
       
    });

    ws.on('close', function() {
        if (ws.isClosing) {
            // console.log(`Пользователь с SteamID ${ws.closingSteamID} закрывает соединение`);
            if(ws.closingSteamID != null){
                activeUsers.delete(ws.closingSteamID);
                broadcastActiveUsers();
            }
        }
    });

    function broadcastActiveUsers() {
        // Формируем список активных пользователей и отправляем его всем подключенным клиентам
        wss.clients.forEach(function each(client) {
            if (client.readyState === WebSocket.OPEN) {
                //создаём массив из пользователей
                const usersArray = Array.from(activeUsers).map(([steamid, userInfo]) => [steamid, userInfo]);

                // Сортируем по никнейму
                usersArray.sort((a, b) => a[1].nickname.localeCompare(b[1].nickname));

                // Отправляем отсортированный массив клиенту
                client.send(JSON.stringify({ action: 'updateUsers', users: [...usersArray] }));
            }
        });
    }
})

async function authenticateToken(req, res, next) {
    const token = req.cookies.access_token;
    const sql = "SELECT steamid, nickname, img, messages FROM `message_history` WHERE 1;";
    const history_messages = await query(sql);
    let model = {
        Title: "Test Room",
        history: history_messages
    };

    if (token == null) return res.render(path.join(__dirname+'/html/index'), model);

    jwt.verify(token, "secket_key", (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

//__dirname : It will resolve to your project folder.

async function getMessagesHistory() {
    const sql = "SELECT steamid, nickname, img, messages FROM `message_history` WHERE 1;";
    try {
        return await query(sql);
    } catch (error) {
        console.error("Ошибка при получении истории сообщений: ", error);
        throw error; // Перебрасываем ошибку дальше
    }
}

app.get('/', authenticateToken, async (req, res) => { 
    try {
        const history_messages = await getMessagesHistory();

        let profile = [];
        if (req.user) {
            const steamApiUrl = `http://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=${config.apiKey}&steamids=${req.user}`;
            const response = await axios.get(steamApiUrl);
            profile.push(response.data.response.players[0]);
        }
        
        let model = {
            Title: "Test Room",
            jsonSteam: profile.length > 0 ? profile[0] : null,
            history: history_messages
        };

        res.render(path.join(__dirname+'/html/index'), model);
    } catch (error) {
        console.error("Ошибка при загрузке главной страницы: ", error);
        res.status(500).send("Ошибка сервера");
    }
});

app.get('/api/auth/steam', passport.authenticate('steam', {failureRedirect: '/'}), function (req, res) {
    res.redirect('/');
});
app.get('/api/auth/steam/return', passport.authenticate('steam', {failureRedirect: '/'}), function (req, res) {
    // JWT уже установлен в профиле пользователя
    let currentDate = new Date();
    currentDate.setMonth(currentDate.getMonth() + 1);
    res.cookie('access_token', req.user.accessToken, { httpOnly: false, secure: true, expires: currentDate });
    res.redirect('/');
});

app.get('/404', function(req,res){
    res.status(404).sendFile(path.join(__dirname+'/html/404.html'));
});

server.listen(config.port, config.hostname, () => {
    console.debug(`Server listening on port https://${config.hostname}:${config.port}`);
});