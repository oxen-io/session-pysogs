
const makebuffer = (raw) => {
    let b = Uint8Array.from(window.atob(raw), (v) => v.charCodeAt(0));
    // This data is padded with a 0x80 delimiter followed by any number of 0x00 bytes, but these are
    // *not* part of the protocol buffer encoding, so we need to strip it off.
    let realLength = b.length;
    while (realLength > 0 && b[realLength-1] == 0)
        realLength--;
    if (realLength > 0 && b[realLength-1] == 0x80)
        realLength--;
    return b.subarray(0, realLength);
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
            const req = await fetch(`/room/${window.view_room}/messages/recent`);
            const msgs = await req.json();



            elem.replaceChildren();

            if(msgs.length === 0)
            {
                elem.appendChild(document.createTextNode(`the ${window.view_room} room is empty`));
            }

            for(let msg of msgs.reverse())
            {
                let e = document.createElement("li")
                try
                {
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
