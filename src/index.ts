import {
    ApplicationMessage,
    ApplicationMessageHeader,
    Connect,
    Disconnect,
    IApplicationMessage,
    MmtpMessage,
    MsgType,
    ProtocolMessage,
    ProtocolMessageType,
    Receive,
    Recipients,
    Send,
    Subscribe,
    Unsubscribe
} from "../mmtp";
import {v4 as uuidv4} from "uuid";
import "./styles.scss";
import "bootstrap";

console.log("Hello World!");

let ownMrn = "urn:mrn:mcp:device:idp1:org1:" + uuidv4().slice(0, 8);

const connectContainer = document.getElementById("connectContainer") as HTMLDivElement;
const receiveContainer = document.getElementById("receiveContainer") as HTMLDivElement;
const urlInput = document.getElementById("edgeRouterAddr") as HTMLSelectElement;
const nameInput = document.getElementById("nameField") as HTMLInputElement;
const mrnInput = document.getElementById("mrnField") as HTMLInputElement;
const connectBtn = document.getElementById("connectBtn") as HTMLButtonElement;

const mrnH3 = document.getElementById("mrnH3") as HTMLTextAreaElement;
mrnH3.textContent = ownMrn;

const msgContainer = document.getElementById("msgContainer") as HTMLDivElement;
const msgArea = document.getElementById("msgArea") as HTMLTextAreaElement;
const receiverSelect = document.getElementById("receiver") as HTMLSelectElement;
const receiverMrnSelect = document.getElementById("receiverMrn") as HTMLSelectElement;
const sendBtn = document.getElementById("sendBtn") as HTMLButtonElement;
const disconnectBtn = document.getElementById("disconnectBtn") as HTMLButtonElement;
const incomingArea = document.getElementById("incomingArea") as HTMLTextAreaElement;

const subsList = document.getElementById("subscriptions") as HTMLUListElement;
const subjectSelect = document.getElementById("subjectSelect") as HTMLSelectElement;

interface Subscription {
    value: string,
    name: string,
}

const possibleSubscriptions: Subscription[] = [
    {
        value: "Urn:mrn:mcp:service:dk-dmi:weather_on_route",
        name: "Weather on route",
    },
    {
        value: "Boats",
        name: "Boats",
    },
    {
        value: "MCP",
        name: "MCP",
    },
    {
        value: "Weather",
        name: "Weather",
    }];

let encodedFile: Uint8Array;

const mrnStoreUrl = "http://20.91.195.244";

interface Agent {
    mrn: string,
    edgeRouter: string,
}

const mrnRadio = document.getElementById('mrn') as HTMLInputElement;
const subjectRadio = document.getElementById('subject') as HTMLInputElement;

// MRN 라디오 버튼에 이벤트 리스너 추가
mrnRadio.addEventListener('change', (event) => {
    if (mrnRadio.checked) {
        subjectSelect.hidden = true;
        receiverMrnSelect.hidden = false;
        fetch(mrnStoreUrl + "/mrns", {
            mode: "cors",
            method: "GET"
        })
            .then(resp => resp.json())
            .then((resp: Agent[]) => resp.forEach(agent => {
                if (agent.mrn !== ownMrn) {
                    const mrnOption = document.createElement("option");
                    mrnOption.value = agent.mrn;
                    mrnOption.textContent = agent.mrn;
                    receiverMrnSelect.appendChild(mrnOption);
                }
            }));
    }
});

// Subject 라디오 버튼에 이벤트 리스너 추가
subjectRadio.addEventListener('change', (event) => {
    if (subjectRadio.checked) {
        receiverMrnSelect.hidden = true;
        receiverMrnSelect.innerHTML = "<option value=\"\">---Please select an MRN---</option>";
        subjectSelect.hidden = false;
    }
});

possibleSubscriptions.forEach(ps => {
    const li = document.createElement("li");
    li.classList.add("list-group-item");

    const span = document.createElement("span");
    span.textContent = ps.name;
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
                    subject: ps.value
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
                    subject: ps.value
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
    subjectOption.value = ps.value;
    subjectOption.textContent = ps.name;
    subjectSelect.appendChild(subjectOption);
});

nameInput.addEventListener("keyup", () => {
    const nameInput = document.getElementById("nameField") as HTMLInputElement;
    let name = nameInput.value;
    name = name.toLowerCase().trim().replace(/\s+/g, "-");
    ownMrn = "urn:mrn:mcp:device:idp1:org1:" + name;
    mrnInput.value = ownMrn;
})


let ws: WebSocket;
let reconnectToken: string;
let lastSentMessage: MmtpMessage;

const fileBytesArray = new TextEncoder().encode("FILE"); // The bytes of the word "FILE"

connectBtn.addEventListener("click", () => {
    let wsUrl = urlInput.value;
    if (wsUrl === "") {
        alert("You need to choose an Edge Router to connect to!");
        location.reload();
    } else if (!wsUrl.startsWith("ws")) {
        wsUrl = "ws://" + wsUrl;
    }

    const edgeRouter = urlInput.options[urlInput.selectedIndex].textContent;

    const nameInput = document.getElementById("nameField") as HTMLInputElement;
    let name = nameInput.value;
    if (name !== "") {
        name = name.toLowerCase().trim().replace(/\s+/g, "-");
        ownMrn = "urn:mrn:mcp:device:idp1:org1:" + name;
        mrnH3.textContent = ownMrn;
    }

    mrnH3.hidden = false;

    ws = new WebSocket(wsUrl);

    ws.addEventListener("open", () => {
        let initialized = false;

        ws.onmessage = async (msgEvent) => {
            console.log("Message received:", msgEvent.data);
            const data = msgEvent.data as Blob;
            const bytes = await data.arrayBuffer();
            const response = MmtpMessage.decode(new Uint8Array(bytes));
            console.log(response);

            if (response.responseMessage?.responseToUuid !== lastSentMessage.uuid) {
                console.error("The UUID of the last sent message does not match the UUID being responded to");
            }
            if (!initialized) {
                // do something
                connectContainer.hidden = true;
                msgContainer.hidden = false;
                reconnectToken = response.responseMessage.reconnectToken;

                const subMsg = MmtpMessage.create({
                    msgType: MsgType.PROTOCOL_MESSAGE,
                    uuid: uuidv4(),
                    protocolMessage: ProtocolMessage.create({
                        protocolMsgType: ProtocolMessageType.SUBSCRIBE_MESSAGE,
                        subscribeMessage: Subscribe.create({
                            directMessages: true
                        })
                    })
                });
                msgBlob = MmtpMessage.encode(subMsg).finish();

                lastSentMessage = subMsg;
                initialized = true;

                ws.send(msgBlob);

                disconnectBtn.addEventListener("click", () => {
                    const disconnectMsg = MmtpMessage.create({
                        msgType: MsgType.PROTOCOL_MESSAGE,
                        uuid: uuidv4(),
                        protocolMessage: ProtocolMessage.create({
                            protocolMsgType: ProtocolMessageType.DISCONNECT_MESSAGE,
                            disconnectMessage: Disconnect.create()
                        })
                    });

                    msgBlob = MmtpMessage.encode(disconnectMsg).finish();

                    lastSentMessage = disconnectMsg;
                    ws.send(msgBlob);
                });

                await fetch(mrnStoreUrl + "/mrn", {
                    method: "POST",
                    body: JSON.stringify({mrn: ownMrn, edgeRouter: edgeRouter}),
                    mode: "cors",
                    headers: {"Content-Type": "application/json"}
                });

                disconnectBtn.hidden = false;
                receiveContainer.hidden = false;
            } else {
                if (response.msgType == MsgType.RESPONSE_MESSAGE) {
                    const msgs = response.responseMessage.applicationMessages;
                    msgs.forEach(msg => {
                        showReceivedMessage(msg);
                    })
                }
            }
        };

        const connectMsg = MmtpMessage.create({
            msgType: MsgType.PROTOCOL_MESSAGE,
            uuid: uuidv4(),
            protocolMessage: ProtocolMessage.create({
                protocolMsgType: ProtocolMessageType.CONNECT_MESSAGE,
                connectMessage: Connect.create({
                    ownMrn: ownMrn
                })
            })
        });
        if (reconnectToken) {
            connectMsg.protocolMessage.connectMessage.reconnectToken = reconnectToken;
        }
        let msgBlob = MmtpMessage.encode(connectMsg).finish();

        lastSentMessage = connectMsg;
        ws.send(msgBlob);
    });

    ws.addEventListener("close", evt => {
        if (evt.code !== 1000) {
            alert("Connection to Edge Router closed unexpectedly: " + evt.reason);
        }
        fetch(mrnStoreUrl + "/mrn/" + ownMrn, {
            method: "DELETE",
            mode: "cors"
        }).then(() => location.reload());
    });
});

function showReceivedMessage(msg: IApplicationMessage) {
    const payload = msg.body;
    const decoder = new TextDecoder();
    if (arraysEqual(payload.subarray(0, 4), fileBytesArray)) {
        for (let i = 4; i < payload.length; i++) {
            if (arraysEqual(payload.subarray(i, i + 4), fileBytesArray)) {
                const fileNameBytes = payload.subarray(4, i);
                const fileName = decoder.decode(fileNameBytes);
                const content = payload.subarray(i + 4);

                incomingArea.append(`${msg.header.sender} sent: `);
                const downloadLink = document.createElement("a");
                downloadLink.href = "#";
                downloadLink.textContent = fileName;
                downloadLink.onclick = (e) => {
                    let hidden_a = document.createElement('a');
                    hidden_a.setAttribute('href', 'data:application/octet-stream;base64,' + bytesToBase64(content));
                    hidden_a.setAttribute('download', fileName);
                    document.body.appendChild(hidden_a);
                    hidden_a.click();

                    e.preventDefault();
                };
                incomingArea.append(downloadLink);
                incomingArea.appendChild(document.createElement('br'));
                break;
            }
        }
    } else {
        const text = decoder.decode(payload);
        incomingArea.append(`${msg.header.sender} sent: ${text}`);
        incomingArea.appendChild(document.createElement('br'));
    }
}

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length)
        return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i])
            return false;
    }
    return true;
}

function bytesToBase64(bytes: Uint8Array): string {
    const binString = Array.from(bytes, (x) => String.fromCodePoint(x)).join("");
    return btoa(binString);
}

sendBtn.addEventListener("click", () => {
    if (!mrnRadio.checked && !subjectRadio.checked) {
        alert("You need to choose message type!");
    }

    let bytes: Uint8Array;
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
                        sender: ownMrn
                    }),
                    body: bytes
                })
            })
        })
    });

    if (mrnRadio.checked) {
        const receiver = receiverMrnSelect.options[receiverMrnSelect.selectedIndex].value;
        sendMsg.protocolMessage.sendMessage.applicationMessage.header.recipients = Recipients.create({
            recipients: [receiver]
        });
    } else if (subjectRadio.checked) {
        sendMsg.protocolMessage.sendMessage.applicationMessage.header.subject = subjectSelect.options[subjectSelect.selectedIndex].value;
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

function encodeFile(fileName: string, data: Uint8Array): Uint8Array {
    const fileNameArray = new TextEncoder().encode("FILE" + fileName + "FILE");
    const mergedArray = new Uint8Array(fileNameArray.length + data.length);
    mergedArray.set(fileNameArray);
    mergedArray.set(data, fileNameArray.length);
    return mergedArray;
}

const fileInput = document.getElementById('fileInput');
fileInput.addEventListener("change", handleFiles, false);

function handleFiles() {
    const fileList = this.files; /* now you can work with the file list */

    const file: File = this.files[0];
    if (file) {
        file.arrayBuffer().then(buff => {
            let data = new Uint8Array(buff); // x is your uInt8Array
            // perform all required operations with x here.
            encodedFile = encodeFile(file.name, data);
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
    const file = new Blob([content], {type: "text/plain"});

    downloadLink.download = fileName;
    downloadLink.href = URL.createObjectURL(file);
    downloadLink.click();
}
