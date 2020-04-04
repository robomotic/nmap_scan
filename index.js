const express = require('express');
const os = require('os');
const { promisify } = require('util');
const { spawn } = require('child_process');
const exec = promisify(require('child_process').exec);

const redis = require("redis");
const redis_client = redis.createClient(process.env.REDIS_URL);

redis_client.on("error", function(error) {
  console.error(error);
});

var cache = require('express-redis-cache')({
  client: redis_client
  });

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
  let errors = '';

  console.log(`run scan: ${host}`);
  const command = spawn('nmap', flags.concat([host]));
  for await (const data of command.stdout) {
    results = results + data;
  }

  for await (const data of command.stderr) {
    errors = errors + data;
  }
  console.log(`scan completed: ${host}`);

  return [results.toString(),errors.toString()];
}


app.get('/version',cache.route('scan',1), async(req, res) => {
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

app.get('/cache/:hostname',
  authSimple,
  async(req, res) => {
  const host = req.params.hostname;
  const operation = req.query.operation;
  if (!host) {
    res.set(500);
    return res.send('Must include a host param to lookup');
  }

  redis_client.get('host-' + host, function(err, response) {
    if (err === null) {
        res.set(500);
        res.send(err);
    } else{
      res.set(response);
    }
  })

});

app.delete('/cache2/:hostname',
  authSimple,
  async(req, res) => {
  const host = req.params.hostname;

  if (!host) {
    res.set(500);
    return res.send('Must include a host param to lookup');
  }

  redis_client.del('host-' + host, function(err, response) {
    if (response == 1) {
      res.send(response);
    } else{
      res.set(500);
      res.send(err);
    }
  })
});

app.delete('/cache/:hostname',
  authSimple,
  async(req, res) => {
  const host = req.params.hostname;


  cache.get(function (error, entries) {
    if ( error ) throw error;
   
    entries.forEach(console.log.bind(console));
  });
  
  if (!host) {
    res.set(500);
    return res.send('Must include a host param to lookup');
  }

  cache.del('host-'+host,function (error, deletions) {
    if ( error ){
      return res.sendStatus(404);
    }
    else{
      console.log('Deleted ' + deletions);
      res.sendStatus(204);
    }
  });

});


app.get('/scan/:hostname',
  authSimple,
  function (req, res, next) {
    // set cache name
    if (req.params.hostname) {
      res.express_redis_cache_name = 'host-' + req.params.hostname;
      next();
      }
    },
  cache.route({expire:60}), 
  async(req, res) => {
  const host = req.params.hostname;
  const nflags = req.query.flags;
  if (!host) {
    return res.send('Must include a host param to scan');
  }
  let results = null;
  let errors = null;
  try {
    if (!nflags)
    {
      [results,errors] = await runScan(host,['-oX','-']);
    }
    else{
      [results,errors] = await runScan(host,nflags.split("|"));
    }

    if (errors == null || errors=='')
    {
      res.send(results);
    }
    else{
      res.set(500);
      res.send(errors);
    }
  } catch (err) {
    console.log(`error: ${err}`);
    res.set(500);
    res.send(err);
  }
});

app.listen(3000, () => console.log("namp scanner listening"));
