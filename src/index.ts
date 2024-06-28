import {
    ApplicationMessage,
    ApplicationMessageHeader,
    Connect,
    Disconnect,
    Filter,
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
import {Certificate} from "pkijs";
import {fromBER, Integer, Sequence} from "asn1js";
import {bufToBigint} from "bigint-conversion";
import {ResponseSearchObject} from "./SecomSearch";
import {SmmpHeader, SmmpMessage} from "../smmp";

console.log("Hello World!");

let ownMrn = "";

const connectContainer = document.getElementById("connectContainer") as HTMLDivElement;
const receiveContainer = document.getElementById("receiveContainer") as HTMLDivElement;
const urlInput = document.getElementById("edgeRouterAddr") as HTMLSelectElement;
const connectBtn = document.getElementById("connectBtn") as HTMLButtonElement;

const connTypeSelect = document.getElementById("connectionTypeSelect") as HTMLSelectElement;
const certInputDiv = document.getElementById("certInputDiv") as HTMLDivElement;
const certFileInput = document.getElementById("certInput") as HTMLInputElement;
const privateKeyFileInput = document.getElementById("privateKeyInput") as HTMLInputElement;

const mrnH3 = document.getElementById("mrnH3") as HTMLTextAreaElement;

const msgContainer = document.getElementById("msgContainer") as HTMLDivElement;
const sendContainer = document.getElementById("sendContainer") as HTMLDivElement;
const msgArea = document.getElementById("msgArea") as HTMLTextAreaElement;
const receiverMrnSelect = document.getElementById("receiverMrn") as HTMLSelectElement;
const sendBtn = document.getElementById("sendBtn") as HTMLButtonElement;
const disconnectBtn = document.getElementById("disconnectBtn") as HTMLButtonElement;
const incomingArea = document.getElementById("incomingArea") as HTMLDivElement;

const subsList = document.getElementById("subscriptions") as HTMLUListElement;
const subjectSelect = document.getElementById("subjectSelect") as HTMLSelectElement;

//All SMMP relevant items
const smmpMenu = document.getElementById("smmpMenu") as HTMLDivElement
const smmpConnectBtn = document.getElementById("smmpConnectBtn") as HTMLButtonElement;


const mrnStoreUrl = "https://mrn-store.dmc.international";
const msrSecomSearchUrl = "https://msr.maritimeconnectivity.net/api/secom/v1/searchService";

const greenCheckMark = "\u2705";


interface Subject {
    value: string,
    name: string,
}

interface ServiceProvider {
    mrn: string,
    certificates: Certificate[]
}

interface Subscription {
    subject: string,
    serviceProviders: ServiceProvider[]
}

const subscriptions: Map<string, Subscription> = new Map();

let authenticated: boolean;
let connectionType: string;

connTypeSelect.addEventListener("change", () => {
    authenticated = connTypeSelect.value === "authenticated";
    connectionType = connTypeSelect.value;
    certInputDiv.hidden = !authenticated;
});

let certificate: Certificate;
let privateKey: CryptoKey;

let ws: WebSocket;
let reconnectToken: string;
let lastSentMessage: MmtpMessage;

connectBtn.addEventListener("click", async () => {
    if (!connectionType) {
        alert("Please choose a connection type");
        location.reload();
    }

    if (authenticated) {
        await loadCertAndPrivateKeyFromFiles();
        for (const rdn of certificate.subject.typesAndValues) {
            if (rdn.type === "0.9.2342.19200300.100.1.1") {
                ownMrn = rdn.value.valueBlock.value;
                mrnH3.textContent = ownMrn;
                mrnH3.hidden = false;
                break;
            }
        }
        console.log(ownMrn);
    }

    let wsUrl = urlInput.value;
    if (wsUrl === "") {
        alert("You need to choose an Edge Router to connect to!");
        location.reload();
    } else if (!wsUrl.startsWith("ws")) {
        wsUrl = "ws://" + wsUrl;
    }
    const edgeRouter = urlInput.options[urlInput.selectedIndex].textContent;

    ws = new WebSocket(wsUrl);

    ws.addEventListener("open", () => {
        let initialized = false;

        ws.onmessage = async (msgEvent) => {
            console.log("Message received:", msgEvent.data);
            const data = msgEvent.data as Blob;
            const bytes = await data.arrayBuffer();
            const mmtpMessage = MmtpMessage.decode(new Uint8Array(bytes));
            console.log(mmtpMessage);

            if (mmtpMessage.msgType === MsgType.RESPONSE_MESSAGE && mmtpMessage.responseMessage?.responseToUuid !== lastSentMessage.uuid) {
                console.error("The UUID of the last sent message does not match the UUID being responded to");
            }
            if (!initialized) {
                // do something
                connectContainer.hidden = true;
                msgContainer.hidden = false;
                reconnectToken = mmtpMessage.responseMessage.reconnectToken;

                if (authenticated) {
                    sendContainer.hidden = false;
                    smmpMenu.hidden = false;
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

                    ws.send(msgBlob);
                }
                initialized = true;

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

                if (ownMrn) {
                    await fetch(mrnStoreUrl + "/mrn", {
                        method: "POST",
                        body: JSON.stringify({mrn: ownMrn, edgeRouter: edgeRouter}),
                        mode: "cors",
                        headers: {"Content-Type": "application/json"}
                    });
                }

                disconnectBtn.hidden = false;
                receiveContainer.hidden = false;
            } else {
                if (mmtpMessage.msgType === MsgType.RESPONSE_MESSAGE) {
                    const msgs = mmtpMessage.responseMessage.applicationMessages;
                    for (const msg of msgs) {
                        const validSignature = await verifySignatureOnMessage(msg);

                        //Check if SMMP and in that case handle it as SMMP
                        let msgIsSmmp = await isSmmp(msg)
                        if (msgIsSmmp) {
                            const smmpMessage = SmmpMessage.decode(new Uint8Array(msg.body));
                            const flags : number = smmpMessage.header.control[1]
                            //Handle cases of SMMP messages
                            console.log("flags", flags)
                            if (hasFlags(flags, [FlagsEnum.Handshake, FlagsEnum.Confidentiality])) {
                                console.log("Handshake initiation")

                                // 2nd step handshake
                                if (hasFlags(flags, [FlagsEnum.Handshake, FlagsEnum.Confidentiality, FlagsEnum.ACK])) {

                                // 1st step handshake
                                } else {

                                }
                            // Case - Reception of an ACK of a received message with delivery guarantee
                            } else if (hasFlags(flags, [FlagsEnum.ACK, FlagsEnum.Confidentiality, FlagsEnum.DeliveryGuarantee])) {

                            // Case - last part of three-way handshake, i.e. 3rd step of three-way handshake
                            } else if (hasFlags(flags, [FlagsEnum.ACK, FlagsEnum.Confidentiality])) {

                            // Case regular reception of an encrypted message
                            } else if (hasFlags(flags, [FlagsEnum.Confidentiality])) {

                            }
                        } else {
                            showReceivedMessage(msg, validSignature);
                        }
                    }
                } else if (mmtpMessage.msgType === MsgType.PROTOCOL_MESSAGE && mmtpMessage.protocolMessage?.protocolMsgType === ProtocolMessageType.NOTIFY_MESSAGE) {
                    const notifyMsg = mmtpMessage.protocolMessage.notifyMessage;
                    const uuids = notifyMsg.messageMetadata.map(messageMetadata => messageMetadata.uuid);

                    const receive = MmtpMessage.create({
                        msgType: MsgType.PROTOCOL_MESSAGE,
                        uuid: uuidv4(),
                        protocolMessage: ProtocolMessage.create({
                            protocolMsgType: ProtocolMessageType.RECEIVE_MESSAGE,
                            receiveMessage: Receive.create({
                                filter: Filter.create({
                                    messageUuids: uuids
                                })
                            })
                        })
                    });

                    msgBlob = MmtpMessage.encode(receive).finish();

                    lastSentMessage = receive;
                    ws.send(msgBlob);
                }
            }
        };

        const connectMsg = MmtpMessage.create({
            msgType: MsgType.PROTOCOL_MESSAGE,
            uuid: uuidv4(),
            protocolMessage: ProtocolMessage.create({
                protocolMsgType: ProtocolMessageType.CONNECT_MESSAGE,
                connectMessage: Connect.create({})
            })
        });
        if (ownMrn) {
            connectMsg.protocolMessage.connectMessage.ownMrn = ownMrn;
        }
        if (reconnectToken) {
            connectMsg.protocolMessage.connectMessage.reconnectToken = reconnectToken;
        }
        let msgBlob = MmtpMessage.encode(connectMsg).finish();

        lastSentMessage = connectMsg;
        ws.send(msgBlob);
    });

    ws.addEventListener("close", async evt => {
        if (evt.code !== 1000) {
            alert("Connection to Edge Router closed unexpectedly: " + evt.reason);
        }
        if (ownMrn) {
            await fetch(mrnStoreUrl + "/mrn/" + ownMrn, {
                method: "DELETE",
                mode: "cors"
            });
        }
        location.reload();
    });
});

async function isSmmp(msg: IApplicationMessage): Promise<boolean> {
    console.log("Ismessage");
    let smmpMessage: SmmpMessage;
    try {
        smmpMessage = SmmpMessage.decode(new Uint8Array(msg.body));
    } catch (error) {
        console.log("Message could not be parsed as smmp:", error);
        return false;
    }
    console.log("Complete");

    // Define the magic bytes
    const magicBytes = new Uint8Array([0x50, 0x4D, 0x4D, 0x53]); // Ascii PMMS
    const dataView = new DataView(magicBytes.buffer);
    const magicInt = dataView.getInt32(0, false); // false for Big Endian

    // Ensure smmpMessage.header and smmpMessage.header.magic are defined
    if (!smmpMessage.header || smmpMessage.header.magic == null) {
        return false;
    }

    // Extract the magic value from the message
    const extractedMagic = smmpMessage.header.magic;

    // Compare the magic values
    return magicInt === extractedMagic;
}


let certBytes: ArrayBuffer;
async function loadCertAndPrivateKeyFromFiles() {
    if (!certFileInput.files.length || !privateKeyFileInput.files.length) {
        alert("Please provide a certificate and private key file")
        location.reload()
    }

    const certString = await certFileInput.files[0].text();
    if (certString.startsWith("-----BEGIN")) { // Is this PEM encoded?
        certBytes = extractFromPem(certString, "CERTIFICATE");
    } else { // Nope, it is probably just DER encoded then
        certBytes = await certFileInput.files[0].arrayBuffer();
    }

    const privKeyString = await privateKeyFileInput.files[0].text();
    let privKeyBytes: ArrayBuffer;
    if (privKeyString.startsWith("-----BEGIN")) {
        privKeyBytes = extractFromPem(privKeyString, "PRIVATE KEY");
    } else {
        privKeyBytes = await privateKeyFileInput.files[0].arrayBuffer();
    }

    certificate = Certificate.fromBER(certBytes);
    privateKey = await crypto.subtle.importKey("pkcs8", privKeyBytes, {
        name: "ECDSA",
        namedCurve: "P-384"
    }, false, ["sign"]);

}

function extractFromPem(pemInput: string, inputType: string): ArrayBuffer {
    const b64 = pemInput.split(new RegExp(`-----BEGIN ${inputType}-----\r?\n?`))[1].split(`-----END ${inputType}-----`)[0];
    return str2ab(atob(b64));
}

/*
Convert a string into an ArrayBuffer
from https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String
*/
function str2ab(str: string) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

const possibleSubscriptions: Subject[] = [
    {
        value: "urn:mrn:mcp:service:dk-dmi:weather_on_route",
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
    },
    {
        value: "NW-AU",
        name: "NW from Australia"
    },
    {
        value: "s125",
        name: "S125",
    }
];

let encodedFile: Uint8Array;

interface Agent {
    mrn: string,
    edgeRouter: string,
}

const mrnRadio = document.getElementById('mrn') as HTMLInputElement;
const subjectRadio = document.getElementById('subject') as HTMLInputElement;

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

subjectRadio.addEventListener('change', (event) => {
    if (subjectRadio.checked) {
        receiverMrnSelect.hidden = true;
        receiverMrnSelect.innerHTML = "<option value=\"\">---Please select an MRN---</option>";
        subjectSelect.hidden = false;
    }
});

let nwSubjectName: string;

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

    subButton.addEventListener("click", async () => {
        let subject = ps.value;
        if (ps.value === "NW-AU") {
            const auWkt = "POLYGON ((-257.167969 -26.902477, -242.753906 -14.774883, -227.285156 -7.885147, -206.71875 -12.21118, -203.027344 -36.597889, -213.222656 -47.872144, -250.488281 -39.504041, -257.167969 -26.902477))";
            const body = {
                query: {
                    dataProductType: "S124"
                },
                geometry: auWkt
            };
            const response = await fetch(msrSecomSearchUrl, {
                method: "POST",
                body: JSON.stringify(body),
                headers: {
                    "Content-Type": "application/json"
                }
            });
            const responseSearchObject: ResponseSearchObject = await response.json();
            for (const sr of responseSearchObject.searchServiceResult) {
                if (sr.endpointUri.startsWith("urn:mrn")) { // this is an MMS subject
                    subject = sr.endpointUri;
                    nwSubjectName = subject;
                    const certs: Certificate[] = sr.certificates?.map(c => {
                        const pem = c.certificate;
                        const der = extractFromPem(pem, "CERTIFICATE");
                        return Certificate.fromBER(der);
                    }, []);
                    const serviceProvider: ServiceProvider = {
                        mrn: sr.instanceId,
                        certificates: certs
                    };
                    let subscription = subscriptions.get(subject);
                    if (!subscription) {
                        subscription = {
                            subject: subject,
                            serviceProviders: []
                        };
                    }
                    subscription.serviceProviders.push(serviceProvider);
                    subscriptions.set(subject, subscription);
                    // right now we just handle the first result we find
                    break;
                }
            }
        }
        const subMsg = MmtpMessage.create({
            uuid: uuidv4(),
            msgType: MsgType.PROTOCOL_MESSAGE,
            protocolMessage: ProtocolMessage.create({
                protocolMsgType: ProtocolMessageType.SUBSCRIBE_MESSAGE,
                subscribeMessage: Subscribe.create({
                    subject: subject
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
        let subject = ps.value;
        if (subject === "NW-AU") {
            subject = nwSubjectName;
        }
        const unsubMsg = MmtpMessage.create({
            uuid: uuidv4(),
            msgType: MsgType.PROTOCOL_MESSAGE,
            protocolMessage: ProtocolMessage.create({
                protocolMsgType: ProtocolMessageType.UNSUBSCRIBE_MESSAGE,
                unsubscribeMessage: Unsubscribe.create({
                    subject: subject
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

interface SignatureVerificationResponse {
    valid: boolean,
    signer?: string,
    serialNumber?: bigint
}

async function verifySignatureOnMessage(msg: IApplicationMessage): Promise<SignatureVerificationResponse> {
    // Currently we only check subject-casts
    if (msg.header.subject) {
        const signatureSequence = fromBER(msg.signature).result as Sequence;
        let r = (signatureSequence.valueBlock.value.at(0) as Integer).valueBlock.valueHexView;
        if (r.length === 49) {
            r = r.subarray(1, r.length);
        }
        let s = (signatureSequence.valueBlock.value.at(1) as Integer).valueBlock.valueHexView;
        if (s.length === 49) {
            s = s.subarray(1, s.length);
        }
        const rawSignature = new Uint8Array(r.length + s.length);
        rawSignature.set(r, 0);
        rawSignature.set(s, r.length);

        const subject = msg.header.subject;

        let uint8Arrays: Uint8Array[] = [];
        const textEncoder = new TextEncoder();
        uint8Arrays.push(textEncoder.encode(subject));
        uint8Arrays.push(textEncoder.encode(msg.header.expires.toString(10)));
        uint8Arrays.push(textEncoder.encode(msg.header.sender));
        uint8Arrays.push(textEncoder.encode(msg.header.bodySizeNumBytes.toString()));
        uint8Arrays.push(msg.body);

        let length = uint8Arrays.reduce((acc, a) => acc + a.length, 0);
        const bytesToBeVerified = new Uint8Array(length);
        let offset = 0;
        for (const array of uint8Arrays) {
            bytesToBeVerified.set(array, offset);
            offset += array.length;
        }

        const subscription = subscriptions.get(subject);
        if (subscription) {
            for (const serviceProvider of subscription.serviceProviders) {
                for (const certificate of serviceProvider.certificates) {
                    const publicKey = await certificate.getPublicKey();
                    const valid = await crypto.subtle.verify({
                        name: "ECDSA",
                        hash: "SHA-384"
                    }, publicKey, rawSignature, bytesToBeVerified);
                    if (valid) {
                        return {
                            valid: true,
                            signer: serviceProvider.mrn,
                            serialNumber: certificate.serialNumber.toBigInt()
                        };
                    }
                }
            }
        }
    }
    return {valid: false};
}

const fileBytesArray = new TextEncoder().encode("FILE"); // The bytes of the word "FILE"

function showReceivedMessage(msg: IApplicationMessage, signatureVerificationResponse: SignatureVerificationResponse) {
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
                break;
            }
        }
    } else {
        const text = decoder.decode(payload);
        incomingArea.append(`${msg.header.sender} sent: ${text}`);
    }
    if (signatureVerificationResponse.valid) {
        const signatureStatusSpan = document.createElement("span");
        signatureStatusSpan.style.marginLeft = "4px";
        signatureStatusSpan.setAttribute("data-toggle", "tooltip");
        signatureStatusSpan.setAttribute("data-placement", "right");
        signatureStatusSpan.textContent = greenCheckMark;
        signatureStatusSpan.title = `The signature was successfully verified using certificate for ${signatureVerificationResponse.signer} with serial number ${signatureVerificationResponse.serialNumber.toString()}`;
        incomingArea.append(signatureStatusSpan);
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

sendBtn.addEventListener("click", async () => {
    if (!mrnRadio.checked && !subjectRadio.checked) {
        alert("You need to choose message type!");
    }


    let body: Uint8Array;
    if (encodedFile) {
        console.log("B1")
        body = encodedFile;
    } else {
        console.log("B2")
        const text = msgArea.value;
        const encoder = new TextEncoder();
        body = encoder.encode(text);
    }

    // set expiration to be one hour from now
    const expires = new Date();
    expires.setTime(expires.getTime() + 3_600_000);

    const sendMsg = MmtpMessage.create({
        msgType: MsgType.PROTOCOL_MESSAGE,
        uuid: uuidv4(),
        protocolMessage: ProtocolMessage.create({
            protocolMsgType: ProtocolMessageType.SEND_MESSAGE,
            sendMessage: Send.create({
                applicationMessage: ApplicationMessage.create({
                    header: ApplicationMessageHeader.create({
                        expires: expires.getTime(),
                        sender: ownMrn,
                        bodySizeNumBytes: body.length,
                    }),
                    body: body,
                })
            })
        })
    });
    let subjectCastMsg : boolean = false

    if (mrnRadio.checked) {
        const receiver = receiverMrnSelect.options[receiverMrnSelect.selectedIndex].value;
        sendMsg.protocolMessage.sendMessage.applicationMessage.header.recipients = Recipients.create({
            recipients: [receiver]
        });
    } else if (subjectRadio.checked) {
        sendMsg.protocolMessage.sendMessage.applicationMessage.header.subject = subjectSelect.options[subjectSelect.selectedIndex].value;
        subjectCastMsg = true
    }

    /*let uint8Arrays: Uint8Array[] = [];
    const encoder = new TextEncoder();

    if (mrnRadio.checked) {
        const receiver = receiverMrnSelect.options[receiverMrnSelect.selectedIndex].value;
        sendMsg.protocolMessage.sendMessage.applicationMessage.header.recipients = Recipients.create({
            recipients: [receiver]
        });
        uint8Arrays.push(encoder.encode(receiver));
    } else if (subjectRadio.checked) {
        const subject = subjectSelect.options[subjectSelect.selectedIndex].value;
        sendMsg.protocolMessage.sendMessage.applicationMessage.header.subject = subject;
        uint8Arrays.push(encoder.encode(subject));
    }

    uint8Arrays.push(encoder.encode(expires.getTime().toString()));
    uint8Arrays.push(encoder.encode(ownMrn));
    uint8Arrays.push(encoder.encode(body.length.toString()));
    uint8Arrays.push(body);

    let length = uint8Arrays.reduce((acc, a) => acc + a.length, 0);

    let bytesToBeSigned = new Uint8Array(length);
    let offset = 0;
    for (const array of uint8Arrays) {
        bytesToBeSigned.set(array, offset);
        offset += array.length;
    }

    const signature = new Uint8Array(await crypto.subtle.sign({
        name: "ECDSA",
        hash: "SHA-384"
    }, privateKey, bytesToBeSigned));

    const r = signature.slice(0, signature.length / 2);
    const s = signature.slice(signature.length / 2, signature.length);

    let sequence = new Sequence();
    sequence.valueBlock.value.push(Integer.fromBigInt(bufToBigint(r)));
    sequence.valueBlock.value.push(Integer.fromBigInt(bufToBigint(s)));
    sendMsg.protocolMessage.sendMessage.applicationMessage.signature = new Uint8Array(sequence.toBER());*/
    let signedSendMsg = await signMessage(sendMsg, subjectCastMsg)

    const toBeSent = MmtpMessage.encode(signedSendMsg).finish();
    console.log("MMTP message: ", signedSendMsg);
    lastSentMessage = signedSendMsg;
    ws.send(toBeSent);
    console.log("MSG SENT!")

    msgArea.value = "";
    encodedFile = undefined;
    loadedState.style.display = 'none';
    unloadedState.style.display = 'block';
});

smmpConnectBtn.addEventListener("click", async () => {
    const rcClientMrn = document.getElementById("rcClientMrn") as HTMLInputElement
    console.log(rcClientMrn.value)

    let smmpMsg = getSmmpHandshakeMessage()
    const smmpPayload = SmmpMessage.encode(smmpMsg).finish()
    let mmtpMsg = getMmtpSendMrnMsg(rcClientMrn.value, smmpPayload)

    let signedSendMsg = await signMessage(mmtpMsg, false)

    const toBeSent = MmtpMessage.encode(signedSendMsg).finish();
    console.log("MMTP message: ", signedSendMsg);
    lastSentMessage = signedSendMsg;
    ws.send(toBeSent);
    console.log("MSG SENT!")

    msgArea.value = "";
    encodedFile = undefined;
    loadedState.style.display = 'none';
    unloadedState.style.display = 'block';
});


//Message receive
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

//Define helper SMMP Functions---------------------------
enum FlagsEnum {
    Handshake = 1 << 0,         // H (bit value 1)
    ACK = 1 << 1,               // A (bit value 2)
    Confidentiality = 1 << 2,   // C (bit value 4)
    DeliveryGuarantee = 1 << 3, // D (bit value 8)
    NonRepudiation = 1 << 4     // N (bit value 16)
}

function setFlags(flags: FlagsEnum[]) : number {
    let result = 0
    for (const flag of flags) {
        result |= flag;
    }
    return result;
}

function hasFlags(val : number, flags : FlagsEnum[]) : boolean {
    for (const flag  of flags) {
        if ((val&flag) === 0) {
            return false
        }
    }
    return true
}

function getMmtpSendMrnMsg(recipientMrn : string, body : Uint8Array) {
    const expires = new Date();
    expires.setTime(expires.getTime() + 3_600_000);

    const sendMsg = MmtpMessage.create({
        msgType: MsgType.PROTOCOL_MESSAGE,
        uuid: uuidv4(),
        protocolMessage: ProtocolMessage.create({
            protocolMsgType: ProtocolMessageType.SEND_MESSAGE,
            sendMessage: Send.create({
                applicationMessage: ApplicationMessage.create({
                    header: ApplicationMessageHeader.create({
                        expires: expires.getTime(),
                        sender: ownMrn,
                        bodySizeNumBytes: body.length,
                    }),
                    body: body,
                })
            })
        })
    });
    sendMsg.protocolMessage.sendMessage.applicationMessage.header.recipients = Recipients.create({
        recipients: [recipientMrn]
    });

    return sendMsg
}




function getSmmpMessage(flags : FlagsEnum[], blcNum : number, totalBlcs : number, smmpUuid : string, smmpData : Uint8Array) {
    const magicBytes = new Uint8Array([0x50, 0x4D, 0x4D, 0x53]); //Ascii PMMS
    const dataView = new DataView(magicBytes.buffer);
    const magicInt = dataView.getInt32(0, false); // false for Big Endian
    let controlBits = setFlags(flags)

    //Due to an unsafe cast in the Go Implementation - TODO: This needs to be changed in both implementations
    const arr = new Uint8Array(2)
    arr[1] = controlBits
    console.log(arr.toString())

    const smmpMsg = SmmpMessage.create({
        header: SmmpHeader.create({
            magic: magicInt,
            control : arr,
            blockNum : blcNum,
            totalBlocks : totalBlcs,
            payloadLen : smmpData.length,
            uuid : smmpUuid
        }),
        data : smmpData
    })
    return smmpMsg
}

function getSmmpHandshakeMessage() {
    const flags : FlagsEnum[] = [FlagsEnum.Handshake, FlagsEnum.Confidentiality, FlagsEnum.DeliveryGuarantee]
    //Get the signing certificate
    return getSmmpMessage(flags, 0, 1, uuidv4(), new Uint8Array(certBytes))
}


function getSmmpHandshakeAckMessage() {
    const flags : FlagsEnum[] = [FlagsEnum.Handshake, FlagsEnum.ACK, FlagsEnum.Confidentiality]
    //Get the signing certificate
    return getSmmpMessage(flags, 0, 1, uuidv4(), new Uint8Array(certBytes))
}

async function signMessage(msg : MmtpMessage, subject : boolean) {
    const appMsgHeader = msg.protocolMessage.sendMessage.applicationMessage.header
    const appMsg = msg.protocolMessage.sendMessage.applicationMessage

    let uint8Arrays: Uint8Array[] = [];
    const encoder = new TextEncoder();

    console.log("Send to ", appMsgHeader.recipients.recipients[0])

    if (subject) {
        uint8Arrays.push(encoder.encode(appMsgHeader.subject));
    } else {
        uint8Arrays.push(encoder.encode(appMsgHeader.recipients.recipients[0]));
    }

    uint8Arrays.push(encoder.encode(appMsgHeader.expires.toString()));
    uint8Arrays.push(encoder.encode(ownMrn));
    uint8Arrays.push(encoder.encode(appMsg.body.length.toString()));
    uint8Arrays.push(appMsg.body);

    let length = uint8Arrays.reduce((acc, a) => acc + a.length, 0);

    let bytesToBeSigned = new Uint8Array(length);
    let offset = 0;
    for (const array of uint8Arrays) {
        bytesToBeSigned.set(array, offset);
        offset += array.length;
    }

    const signature = new Uint8Array(await crypto.subtle.sign({
        name: "ECDSA",
        hash: "SHA-384"
    }, privateKey, bytesToBeSigned));

    const r = signature.slice(0, signature.length / 2);
    const s = signature.slice(signature.length / 2, signature.length);

    let sequence = new Sequence();
    sequence.valueBlock.value.push(Integer.fromBigInt(bufToBigint(r)));
    sequence.valueBlock.value.push(Integer.fromBigInt(bufToBigint(s)));
    msg.protocolMessage.sendMessage.applicationMessage.signature = new Uint8Array(sequence.toBER());

    return msg
}


const loadedState = document.getElementById('file-state-loaded');
const unloadedState = document.getElementById('file-state-unloaded');

loadedState.style.display = 'none';
unloadedState.style.display = 'block';
