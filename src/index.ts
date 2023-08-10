import {
    ApplicationMessage,
    ApplicationMessageHeader,
    Connect,
    MmtpMessage,
    MsgType,
    ProtocolMessage,
    ProtocolMessageType, Receive,
    Recipients,
    Send
} from "../mmtp";
import {v4 as uuidv4} from "uuid";
import "./styles.scss";
import "bootstrap";

console.log("Hello World!");

const mrn = "urn:mrn:mcp:device:idp1:org1:" + uuidv4().slice(0, 8);

let mmtpMsg = MmtpMessage.create({
    msgType: MsgType.PROTOCOL_MESSAGE,
    uuid: uuidv4(),
    protocolMessage: ProtocolMessage.create({
        protocolMsgType: ProtocolMessageType.CONNECT_MESSAGE,
        connectMessage: Connect.create({
            ownMrn: mrn
        })
    })
});

console.log(mmtpMsg);

let msgBlob = MmtpMessage.encode(mmtpMsg).finish();

console.log(msgBlob);

const mrnH3 = document.getElementById("mrnH3") as HTMLTextAreaElement;
mrnH3.textContent = mrn;

const incomingArea = document.getElementById("incomingArea") as HTMLTextAreaElement;

let ws = new WebSocket("ws://localhost:8888");

let initialized = false;

ws.addEventListener("open", () => {
    ws.send(msgBlob);
    ws.onmessage = async (msgEvent) => {
        console.log("Message received:", msgEvent.data);
        let data = msgEvent.data as Blob;
        let bytes = await data.arrayBuffer();
        let response = MmtpMessage.decode(new Uint8Array(bytes));
        console.log(response);
        if (!initialized) {
            // do something
            initialized = true;
        } else {
            if (response.msgType == MsgType.RESPONSE_MESSAGE) {
                const msgs = response.responseMessage.applicationMessages;
                const decoder = new TextDecoder();
                msgs.forEach(msg => {
                    let text = decoder.decode(msg.body);
                    incomingArea.append(`${msg.header.sender} sent: ${text}\n`);
                })
            }
        }
    };
});

const msgArea = document.getElementById("msgArea") as HTMLTextAreaElement;
const receiverInput = document.getElementById("receiver") as HTMLInputElement;
const sendBtn = document.getElementById("sendBtn") as HTMLButtonElement;
sendBtn.addEventListener("click", () => {
    const text = msgArea.value;
    const encoder = new TextEncoder();
    const bytes = encoder.encode(text);
    const receiver = receiverInput.value;

    let sendMsg = MmtpMessage.create({
        msgType: MsgType.PROTOCOL_MESSAGE,
        uuid: uuidv4(),
        protocolMessage: ProtocolMessage.create({
            protocolMsgType: ProtocolMessageType.SEND_MESSAGE,
            sendMessage: Send.create({
                applicationMessage: ApplicationMessage.create({
                    header: ApplicationMessageHeader.create({
                        recipients: Recipients.create({
                            recipients: [receiver]
                        }),
                        bodySizeNumBytes: bytes.byteLength,
                        sender: mrn
                    }),
                    body: bytes
                })
            })
        })
    });
    const toBeSent = MmtpMessage.encode(sendMsg).finish();
    ws.send(toBeSent);
    msgArea.value = "";
    receiverInput.value = "";
});

const receiveBtn = document.getElementById("receiveBtn") as HTMLButtonElement;
receiveBtn.addEventListener("click", () => {
    const receive = MmtpMessage.create({
        msgType: MsgType.PROTOCOL_MESSAGE,
        uuid: uuidv4(),
        protocolMessage: ProtocolMessage.create({
            protocolMsgType: ProtocolMessageType.RECEIVE_MESSAGE,
            receiveMessage: Receive.create({})
        })
    });
    const bytes = MmtpMessage.encode(receive).finish();
    ws.send(bytes);
});
