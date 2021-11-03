
const makebuffer = (raw) => {
    return Uint8Array.from(window.atob(raw), (v) => v.charCodeAt(0));
};
const setup = async () => {
    const elem = document.getElementById("messages");
    if(elem)
    {

        const req = await fetch("/static/session.proto");
        const proto = await req.text();
        const root = protobuf.parse(proto).root;

        const Message = root.lookupType("signalservice.Content");

        const update = async () => {
            const req = await fetch("/room/{{room}}/messages/recent");
            const msgs = await req.json();



            elem.replaceChildren();

            if(msgs.length === 0)
            {
                elem.appendChild(document.createTextNode("the {{room}} room is empty"));
            }

            for(let msg of msgs)
            {
                let e = document.createElement("li")
                try
                {
                    console.log(msg);
                    const data = makebuffer(msg.data);
                    const err = Message.verify(data);
                    if(err)
                    {
                        throw Error(err);
                    }

                    const plain = Message.decode(data).dataMessage;
                    e.appendChild(document.createTextNode(plain.profile.displayName +": "+plain.body));
                    elem.appendChild(e);

                }
                catch(ex)
                {
                    console.log(ex);
                }
            }
        };
        await update();
        setInterval(update, 5000);
    }
};

setTimeout(setup, 0);
