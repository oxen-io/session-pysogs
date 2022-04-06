
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

function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];

    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

const setup = async () => {
    const elem = document.getElementById("messages");
    if(elem)
    {

        const req = await fetch("/static/session.proto");
        const proto = await req.text();
        const root = protobuf.parse(proto).root;

        const Message = root.lookupType("signalservice.Content");
        const url = window.poll_room_url;
        const update = async () => {
            const req = await fetch(url);
            if(req.status != 200)
            {
                elem.replaceChildren();
                elem.appendChild(document.createTextNode(`HTTP {req.status}`));
                return;
            }
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
                    // console.log("VERIFY:")
                    // console.log(data)
                    // console.log(Message.decode(data))
                    // console.log(Message.decode(data).dataMessage)
                    // console.log(Message)
                    // console.log(Message.verify)
                    // console.log(Message.verify(data))

                    // reply
                    if (plain.quote){
                        originalMsg = document.createElement('p');
                        originalMsg.classList.add('text-sm', 'italic', 'border-l-2', 'border-sessionGreen', 'pl-2');

                        // originalMsg = document.getElementById('replyTemplate').cloneNode(true);

                        authorId = plain.quote.author
                        authorId = authorId.substr(authorId.length - 8);
                        originalMsg.appendChild(document.createTextNode("..." + authorId +": "+plain.quote.text));
                        e.appendChild(originalMsg);
                    }
                    
                    // message body
                    e.appendChild(document.createTextNode(plain.profile.displayName +": "+plain.body));
                    e.classList.add('bg-gray-300','dark:bg-lightGray', 'w-fit', 'rounded-lg', 'p-2', 'my-2')
                    elem.appendChild(e);
                    
                    // attachments
                    if (plain.attachments.length > 0){
                        plain.attachments.forEach(attachment => {
                            console.log(attachment);
                            attachmentElement = document.createElement('p');
                            attachmentElement.appendChild(document.createTextNode("📎\xa0\xa0\xa0"));
                            
                                                        attachmentLink = document.createElement('a');
                                                        attachmentLink.appendChild(document.createTextNode((attachment.fileName || attachment.contentType) + ` (${formatBytes(attachment.size)})` ));
                                                        attachmentLink.href = attachment.url;
                                                        attachmentLink.download = (attachment.fileName || "");
                            
                            attachmentElement.appendChild(attachmentLink);
                            attachmentElement.classList.add('text-sm', 'italic', 'pl-1');
                            e.appendChild(attachmentElement);
                        });
                    }

                }
                catch(ex)
                {
                    console.log(ex);
                }
            }
        };
        if(url)
        {
            await update();
            setInterval(update, 60000);
        }
        else
        {
            elem.replaceChildren();
            elem.appendChild(document.createTextNode("no poll url set"));
        }
    }
};

setTimeout(setup, 0);
