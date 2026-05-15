import {
  generateClientId,
  encryptMessage,
  decryptMessage,
  logEvent,
  isString,
  isObject,
  getTime
} from './utils.js';


export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);

      // ========= WebSocket =========

      const upgradeHeader = request.headers.get("Upgrade");

      if (
        upgradeHeader &&
        upgradeHeader.toLowerCase() === "websocket"
      ) {
        const id = env.CHAT_ROOM.idFromName("chat-room");
        const stub = env.CHAT_ROOM.get(id);

        return await stub.fetch(request);
      }

      // ========= API =========

      if (url.pathname.startsWith("/api/")) {
        return Response.json({
          ok: true,
          time: Date.now()
        });
      }

      // ========= 静态资源 =========

      if (!env.ASSETS) {
        return Response.json(
          {
            error: "ASSETS binding missing",
            host: url.hostname,
            path: url.pathname
          },
          {
            status: 500
          }
        );
      }

      try {
        return await env.ASSETS.fetch(request);

      } catch (e) {

        // SPA fallback
        if (
          url.pathname !== "/" &&
          !url.pathname.includes(".")
        ) {

          const indexRequest = new Request(
            new URL("/", request.url)
          );

          return await env.ASSETS.fetch(indexRequest);

        }

        throw e;
      }

    } catch (e) {

      return new Response(
`NodeCrypt Worker Error

${e.stack || e.toString()}
`,
{
status:500,
headers:{
"content-type":"text/plain;charset=UTF-8"
}
}
      );

    }
  }
};



export class ChatRoom {

  constructor(state, env) {

    this.state = state;
    this.env = env;

    this.clients = {};
    this.channels = {};

    this.config = {
      seenTimeout:60000,
      debug:false
    };

    this.keyPair = null;

  }


  async initRSAKeyPair() {

    try {

      let stored = await this.state.storage.get(
        "rsaKeyPair"
      );

      if (!stored) {

        console.log("Generating RSA...");

        const keyPair =
          await crypto.subtle.generateKey(
            {
              name:"RSASSA-PKCS1-v1_5",
              modulusLength:2048,
              publicExponent:new Uint8Array([1,0,1]),
              hash:"SHA-256"
            },
            true,
            ["sign","verify"]
          );

        const [
          publicKeyBuffer,
          privateKeyBuffer
        ] = await Promise.all([

          crypto.subtle.exportKey(
            "spki",
            keyPair.publicKey
          ),

          crypto.subtle.exportKey(
            "pkcs8",
            keyPair.privateKey
          )

        ]);


        stored = {

          rsaPublic:btoa(
            String.fromCharCode(
              ...new Uint8Array(
                publicKeyBuffer
              )
            )
          ),

          rsaPrivateData:Array.from(
            new Uint8Array(
              privateKeyBuffer
            )
          ),

          createdAt:Date.now()

        };


        await this.state.storage.put(
          "rsaKeyPair",
          stored
        );

      }


      const privateKeyBuffer =
        new Uint8Array(
          stored.rsaPrivateData
        );


      stored.rsaPrivate =
        await crypto.subtle.importKey(
          "pkcs8",
          privateKeyBuffer,
          {
            name:"RSASSA-PKCS1-v1_5",
            hash:"SHA-256"
          },
          false,
          ["sign"]
        );


      this.keyPair=stored;

    }

    catch(error){

      console.error(error);

      throw error;

    }

  }



  async fetch(request){

    const upgradeHeader =
      request.headers.get(
        "Upgrade"
      );


    if(
      !upgradeHeader ||
      upgradeHeader.toLowerCase()
      !=="websocket"
    ){

      return new Response(
        "Expected WebSocket",
        {status:426}
      );

    }


    if(!this.keyPair){

      await this.initRSAKeyPair();

    }


    const pair =
      new WebSocketPair();


    const [
      client,
      server
    ] =
      Object.values(pair);


    this.handleSession(
      server
    );


    return new Response(
      null,
      {
        status:101,
        webSocket:client
      }
    );

  }



  async handleSession(connection){

    connection.accept();

    await this.cleanupOldConnections();

    const clientId =
      generateClientId();


    if(
      !clientId ||
      this.clients[clientId]
    ){

      connection.close();

      return;

    }


    this.clients[clientId]={

      connection,

      seen:getTime(),

      key:null,

      shared:null,

      channel:null

    };


    this.sendMessage(

      connection,

      JSON.stringify({

        type:"server-key",

        key:this.keyPair.rsaPublic

      })

    );



    connection.addEventListener(

      "message",

      async(event)=>{

        const message=
          event.data;


        if(
          !isString(message)
        ){

          return;

        }


        if(
          !this.clients[clientId]
        ){

          return;

        }


        this.clients[
          clientId
        ].seen=
        getTime();


        if(
          message==="ping"
        ){

          this.sendMessage(
            connection,
            "pong"
          );

          return;

        }


        if(
          this.clients[
            clientId
          ].shared &&
          message.length<=
          8*1024*1024
        ){

          this.processEncryptedMessage(
            clientId,
            message
          );

        }

      }

    );



    connection.addEventListener(

      "close",

      ()=>{

        delete this.clients[
          clientId
        ];

      }

    );

  }



  processEncryptedMessage(
    clientId,
    message
  ){

    try{

      const decrypted=
        decryptMessage(
          message,
          this.clients[
            clientId
          ].shared
        );


      if(
        !isObject(
          decrypted
        )
      ){

        return;

      }


      logEvent(
        "message",
        decrypted,
        "debug"
      );

    }

    catch(e){

      logEvent(
        "decrypt",
        e,
        "error"
      );

    }

  }



  sendMessage(
    connection,
    message
  ){

    try{

      if(
        connection.readyState
        ===1
      ){

        connection.send(
          message
        );

      }

    }

    catch(e){

      console.log(e);

    }

  }



  async cleanupOldConnections(){

    const threshold=
      getTime()
      -
      this.config
      .seenTimeout;


    for(
      const id
      in this.clients
    ){

      if(
        this.clients[id]
        .seen
        <
        threshold
      ){

        try{

          this.clients[id]
          .connection
          .close();

        }catch{}

        delete this.clients[id];

      }

    }

  }

}
