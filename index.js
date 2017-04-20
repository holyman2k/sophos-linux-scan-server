"use strict";

const cmd = require('node-cmd');
const http = require('http');
const fs = require('fs');
const uuid = require('uuid/v4');
const path = require('path');

const fileFolder = "files";

const hostname = '172.16.160.132';
const port = 3000;

const server = http.createServer((req, res) => {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');

    let data = [];
    req.on('data', function (chunk) {
        data.push(chunk);
    }).on('end', function () {
        const buffer = Buffer.concat(data);
        const folder = path.join(__dirname, fileFolder);
        if (!fs.existsSync(folder)) {
            fs.mkdirSync(folder);
        }
        const filename = path.join(folder, uuid());

        fs.writeFile(filename, buffer, "binary", function (err) {
            if (err) {
                console.log(err);
            } else {
                console.log("The file was saved!");
            }
            scan(filename, (result) => {
                fs.unlink(filename);
                const json = JSON.stringify(result);
                console.log(json);
                res.end(json);
            });
        });
    });
});

server.listen(port, hostname, () => {
    console.log(`Server running at http://${hostname}:${port}/`);
});

function scan(file, callback) {
    const scanner = "/opt/sophos-av/bin/savscan -ss -archive -mime -oe -tnef -pua -suspicious";
    const command = [`${scanner} ${file}`];
    cmd.get(command, function (err, data, stderr) {
        console.log("scan result:", data);
        let viruses = [];
        let okResponse = {
            result: "OK",
        };
        const lines = data.split("\n");
        lines.forEach((line) => {
            if (line.startsWith(">>> Virus")) {
                viruses.push(line.split("'")[1]);
            }
        });
        callback(viruses.length == 0 ? okResponse : viruses);
    });
}
