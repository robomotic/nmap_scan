const express = require('express');
const os = require('os');
const { promisify } = require('util');
const { spawn } = require('child_process');
const exec = promisify(require('child_process').exec);

const app = express();
const TOKEN = process.env.TOKEN || '123abcxyz0000';

const nmap_flags = ['-Pn', '-F', '-sT','-sU'];

const authSimple = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
      const token = authHeader.split(' ')[1];

      if (token==TOKEN) {
          next();
      }
      else{
        return res.sendStatus(403);
      }
  } else {
      res.sendStatus(401);
  }
};

const runScan = async (host,flags=nmap_flags) => {
  let results = '';
  console.log(`run scan: ${host}`);
  const command = spawn('nmap', flags.concat(['-oX','-',host]));
  for await (const data of command.stdout) {
    results = results + data;
  }
  return results.toString();
}


app.get('/version', async(req, res) => {
  try {
    let results = '';
    const command = spawn('nmap', ['-V']);
    for await (const data of command.stdout) {
      results = results + data;
    }
    res.send(results.toString());
  } catch (err) {
    console.log(`error: ${err}`);
    res.set(500);
    res.send(err);
  }
});


app.get('/scan',authSimple, async(req, res) => {
  const host = req.query.host;
  const nflags = req.query.flags;
  if (!host) {
    return res.send('Must include a host param to scan');
  }

  let results;
  try {
    if (!nflags)
    {
      results = await runScan(host);
    }
    else{
      results = await runScan(host,nflags.split("|"));
    }
    res.send(results);
  } catch (err) {
    console.log(`error: ${err}`);
    res.set(500);
    res.send(err);
  }
});


app.listen(3000, () => console.log("listening on 3000"));
