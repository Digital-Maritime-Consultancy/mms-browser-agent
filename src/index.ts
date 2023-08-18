import {
    ApplicationMessage,
    ApplicationMessageHeader,
    Connect, IApplicationMessage,
    MmtpMessage,
    MsgType,
    ProtocolMessage,
    ProtocolMessageType,
    Receive,
    Recipients,
    Send,
    Subscribe, Unsubscribe
} from "../mmtp";
import {v4 as uuidv4} from "uuid";
import "./styles.scss";
import "bootstrap";

console.log("Hello World!");

const mrn = "urn:mrn:mcp:device:idp1:org1:" + uuidv4().slice(0, 8);

const connectContainer = document.getElementById("connectContainer") as HTMLDivElement;
const urlInput = document.getElementById("edgeRouterAddr") as HTMLSelectElement;
const connectBtn = document.getElementById("connectBtn") as HTMLButtonElement;

const mrnH3 = document.getElementById("mrnH3") as HTMLTextAreaElement;
mrnH3.textContent = mrn;

const msgContainer = document.getElementById("msgContainer") as HTMLDivElement;
const msgArea = document.getElementById("msgArea") as HTMLTextAreaElement;
const receiverSelect = document.getElementById("receiver") as HTMLSelectElement;
const receiverInput = document.getElementById("receiverMrn") as HTMLInputElement;
const sendBtn = document.getElementById("sendBtn") as HTMLButtonElement;
const incomingArea = document.getElementById("incomingArea") as HTMLTextAreaElement;

const subsList = document.getElementById("subscriptions") as HTMLUListElement;
const subjectSelect = document.getElementById("subjectSelect") as HTMLSelectElement;

const possibleSubscriptions = ["Horses", "Boats", "MCP"];

var encodedFile: Uint8Array = undefined;

possibleSubscriptions.forEach(ps => {
    const li = document.createElement("li");
    li.classList.add("list-group-item");

    const span = document.createElement("span");
    span.textContent = ps;
    span.classList.add("pe-2");
    li.appendChild(span);

    const subButton = document.createElement("button");
    subButton.classList.add("btn", "btn-primary");
    subButton.textContent = "Subscribe";
    li.appendChild(subButton);

    const unsubButton = document.createElement("button");
    unsubButton.classList.add("btn", "btn-danger");
    unsubButton.textContent = "Unsubscribe";
    unsubButton.hidden = true;
    li.appendChild(unsubButton);

    subButton.addEventListener("click", () => {
        const subMsg = MmtpMessage.create({
            uuid: uuidv4(),
            msgType: MsgType.PROTOCOL_MESSAGE,
            protocolMessage: ProtocolMessage.create({
                protocolMsgType: ProtocolMessageType.SUBSCRIBE_MESSAGE,
                subscribeMessage: Subscribe.create({
                    subject: ps
                })
            })
        });
        const subMsgBytes = MmtpMessage.encode(subMsg).finish();
        lastSentMessage = subMsg;
        ws.send(subMsgBytes);

        subButton.hidden = true;
        unsubButton.hidden = false;
    });

    unsubButton.addEventListener("click", () => {
        const unsubMsg = MmtpMessage.create({
            uuid: uuidv4(),
            msgType: MsgType.PROTOCOL_MESSAGE,
            protocolMessage: ProtocolMessage.create({
                protocolMsgType: ProtocolMessageType.UNSUBSCRIBE_MESSAGE,
                unsubscribeMessage: Unsubscribe.create({
                    subject: ps
                })
            })
        });
        const unsubMsgBytes = MmtpMessage.encode(unsubMsg).finish();
        lastSentMessage = unsubMsg;
        ws.send(unsubMsgBytes);

        unsubButton.hidden = true;
        subButton.hidden = false;
    });

    subsList.appendChild(li);

    const subjectOption = document.createElement("option");
    subjectOption.value = ps;
    subjectOption.textContent = ps;
    subjectSelect.appendChild(subjectOption);
});

receiverSelect.addEventListener("change", () => {
    const selected = receiverSelect.options[receiverSelect.selectedIndex].value;
    switch (selected) {
        case "mrn":
            subjectSelect.hidden = true;
            receiverInput.hidden = false;
            break;
        case "subject":
            receiverInput.hidden = true;
            subjectSelect.hidden = false;
            break;
        default:
            receiverInput.hidden = true;
            subjectSelect.hidden = true;
            break;
    }
});

let ws: WebSocket;
let reconnectToken: string;
let lastSentMessage: MmtpMessage;

connectBtn.addEventListener("click", () => {
    let wsUrl = urlInput.value;
    if (!wsUrl) {
        wsUrl = "ws://localhost:8888";
    } else if (!wsUrl.startsWith("ws")) {
        wsUrl = "ws://" + wsUrl;
    }

    ws = new WebSocket(wsUrl);

    ws.addEventListener("open", () => {
        const mmtpMsg = MmtpMessage.create({
            msgType: MsgType.PROTOCOL_MESSAGE,
            uuid: uuidv4(),
            protocolMessage: ProtocolMessage.create({
                protocolMsgType: ProtocolMessageType.CONNECT_MESSAGE,
                connectMessage: Connect.create({
                    ownMrn: mrn
                })
            })
        });
        if (reconnectToken) {
            mmtpMsg.protocolMessage.connectMessage.reconnectToken = reconnectToken;
        }
        const msgBlob = MmtpMessage.encode(mmtpMsg).finish();

        lastSentMessage = mmtpMsg;
        ws.send(msgBlob);

        let initialized = false;

        ws.onmessage = async (msgEvent) => {
            console.log("Message received:", msgEvent.data);
            const data = msgEvent.data as Blob;
            const bytes = await data.arrayBuffer();
            const response = MmtpMessage.decode(new Uint8Array(bytes));
            console.log(response);

            if (response.responseMessage?.responseToUuid !== lastSentMessage.uuid) {
                alert("The UUID of the last sent message does not match the UUID being responded to");
            }
            if (!initialized) {
                // do something
                connectContainer.hidden = true;
                msgContainer.hidden = false;
                reconnectToken = response.responseMessage.reconnectToken;
                initialized = true;
            } else {
                if (response.msgType == MsgType.RESPONSE_MESSAGE) {
                    const msgs = response.responseMessage.applicationMessages;
                    msgs.forEach(msg => {
                        showReceivedMessage(msg);
                    })
                }
            }
        };
    });
});

function showReceivedMessage(msg: IApplicationMessage) {
    const decoder = new TextDecoder();
    const text = decoder.decode(msg.body);
    if (text.includes("FILE")) {
        var splited = text.split('FILE');

        var filtered = splited.filter(function (el) {
            return el != "";
        });

        const fileName = filtered[0]
        const content = filtered[1]

        incomingArea.append(`${msg.header.sender} sent: `);
        const downloadLink = document.createElement("a");
        downloadLink.href = "#";
        downloadLink.textContent = fileName;
        downloadLink.onclick = (e) => {

            var hidden_a = document.createElement('a');
            hidden_a.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(content));
            hidden_a.setAttribute('download', fileName);
            document.body.appendChild(hidden_a); hidden_a.click();

            e.preventDefault();
        };
        incomingArea.append(downloadLink);
        incomingArea.append('\n');
    } else {
        incomingArea.append(`${msg.header.sender} sent: ${text}\n`);
    }
}

sendBtn.addEventListener("click", () => {
    var bytes;
    if (encodedFile) {
        bytes = encodedFile;
    } else {
        const text = msgArea.value;
        const encoder = new TextEncoder();
        bytes = encoder.encode(text);
    }

    const sendMsg = MmtpMessage.create({
        msgType: MsgType.PROTOCOL_MESSAGE,
        uuid: uuidv4(),
        protocolMessage: ProtocolMessage.create({
            protocolMsgType: ProtocolMessageType.SEND_MESSAGE,
            sendMessage: Send.create({
                applicationMessage: ApplicationMessage.create({
                    header: ApplicationMessageHeader.create({
                        bodySizeNumBytes: bytes.byteLength,
                        sender: mrn
                    }),
                    body: bytes
                })
            })
        })
    });

    const selectedReceiverType = receiverSelect.options[receiverSelect.selectedIndex].value;
    switch (selectedReceiverType) {
        case "mrn":
            const receiver = receiverInput.value;
            sendMsg.protocolMessage.sendMessage.applicationMessage.header.recipients = Recipients.create({
                recipients: [receiver]
            });
            break;
        case "subject":
            const subject = subjectSelect.options[subjectSelect.selectedIndex].value;
            sendMsg.protocolMessage.sendMessage.applicationMessage.header.subject = subject;
            break;
        default:
            alert("You must select a receiver type before sending");
            return;
    }

    const toBeSent = MmtpMessage.encode(sendMsg).finish();
    lastSentMessage = sendMsg;
    ws.send(toBeSent);

    msgArea.value = "";
    encodedFile = undefined;
    loadedState.style.display = 'none';
    unloadedState.style.display = 'block';
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
    lastSentMessage = receive;
    ws.send(bytes);
});

function encodeFileName(fileName: string, data: Uint8Array): Uint8Array {
    return new TextEncoder().encode("FILE" + fileName + "FILE" +new TextDecoder().decode(data));
}

const fileInput = document.getElementById('fileInput');
fileInput.addEventListener("change", handleFiles, false);
function handleFiles() {
    const fileList = this.files; /* now you can work with the file list */

    const file: File = this.files[0];
    if (file) {
        file.arrayBuffer().then(buff => {
            let data = new Uint8Array(buff); // x is your uInt8Array
            const encoded = encodeFileName(file.name, data)
            // perform all required operations with x here.
            encodedFile = encoded;
            this.files = undefined;
            loadedState.style.display = 'block';
            unloadedState.style.display = 'none';
        });
        console.log("call finished");
    }
}

const loadedState = document.getElementById('file-state-loaded');
const unloadedState = document.getElementById('file-state-unloaded');

loadedState.style.display = 'none';
unloadedState.style.display = 'block';

function downloadFile(fileName: string, content: Uint8Array) {
    const downloadLink = document.createElement("a");
    const file = new Blob([content], { type: "text/plain" });

    downloadLink.download = fileName;
    downloadLink.href = URL.createObjectURL(file);
    downloadLink.click();
}
