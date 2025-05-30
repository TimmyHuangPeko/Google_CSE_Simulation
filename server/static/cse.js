
const KEK_SERVER_PORT = "8081"; 
const KMS_ADDRESS = `https://${window.location.hostname}:${KEK_SERVER_PORT}/`;


window.onload = async function() {
    const jwt = localStorage.getItem("jwt")
    if(!jwt){
        document.getElementById("ownlist").innerHTML = "Not Logged in."
        return
    }
    // attach list and upload section
    const uploadResponse = await fetch("/upload", {
        method: "GET",
        headers: { 
            "Authorization": `Bearer ${jwt}`
        }
    });

    const ownListResponse = await fetch("/ownlist", {
        method: "GET",
        headers: { 
            "Authorization": `Bearer ${jwt}`
        }
    });

    const sharedListResponse = await fetch("/sharedlist", {
        method: "GET",
        headers: { 
            "Authorization": `Bearer ${jwt}`
        }
    });


    if (ownListResponse.ok && sharedListResponse.ok && uploadResponse.ok) {
        document.getElementById("upload").innerHTML = await uploadResponse.text();
        document.getElementById("ownlist").innerHTML = await ownListResponse.text();
        document.getElementById("sharedlist").innerHTML = await sharedListResponse.text();
    } else {
        document.getElementById("ownlist").innerHTML = "Failed to load files. Please log in again.";
    }
    

    // handle files upload
    document.getElementById("uploadForm").onsubmit = async function (event) {
        event.preventDefault();
        
        const file = document.getElementById("uploadFile").files[0];

        if (file) {
        // alert(`You Choose: ${file.name}`);
        } else {
            alert("Please select a file to upload.");
            return;
        }


        // Generate AES-GCM key
        const dek_key = await crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256,
            },
            true,
            ["encrypt", "decrypt"]
        );
        // alert(`DEK: ${dek_key}`);


        // Encrypt uploaded file
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const fileArrayBuffer = await file.arrayBuffer();
        const encryptedFile = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv,
            },
            dek_key,
            fileArrayBuffer
        );
        // alert("File encrypted successfully");

        // Request a unique file id for following processing
        const fileIdRespnose = await fetch("/upload", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${localStorage.getItem("jwt")}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({filename: file.name})
        });
        if (!fileIdRespnose.ok) {
            alert("Failed to get file ID");
        }

        const fileIdData = await fileIdRespnose.json();
        const fileId = fileIdData.file_id;

        // 一個kek 一個dek 一組acl 一個owner 一個filename
        // Request key encryption key (KEK) from KMS
        // to-do: use POST request instead (more secure)
        const exportedDek = await crypto.subtle.exportKey("raw", dek_key);
        const exportedDekArray = new Uint8Array(exportedDek);

        function arrayBufferToBase64(buffer) {
            let binary = '';
            const bytes = buffer
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary);
        }
        const dekBase64 = arrayBufferToBase64(exportedDekArray);


        const kmsWrapResponse = await fetch(KMS_ADDRESS + "kms", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${localStorage.getItem("jwt")}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({dek: dekBase64, file_id: fileId, operation: "upload"})
        });
        if (!kmsWrapResponse.ok) {
            errorData = await kmsWrapResponse.json();
            alert(`Failed to wrap DEK: ${errorData.message || "Unknown error"}`);
        }

        const kmsWrapData = await kmsWrapResponse.json();
        alert(`Wrapped DEK: ${kmsWrapData.edek}`);



        function base64ToArrayBuffer(base64) {
            const binary = atob(base64);
            const len = binary.length;
            const bytes = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        }
        const eDekArray = base64ToArrayBuffer(kmsWrapData.edek);
        const eDekData = new Uint8Array(eDekArray);
        

        // Prepare the encrypted file for upload
        const formData = new FormData();

        const encryptedBlob = new Blob([iv, eDekData, encryptedFile], { type: "application/octet-stream" });
        formData.append("file", encryptedBlob, `${file.name}.enc`);


        // Upload the encrypted file and encrypted DEK to the server
        const uploadResponse = await fetch("/upload", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${localStorage.getItem("jwt")}`,
            },
            body: formData,
        });

        if (!uploadResponse.ok) {
            const errorData = await uploadResponse.json();
            alert(`File upload failed: ${errorData.message || "Unknown error"}`);
        }

        const uploadResult = await uploadResponse.json();
        // alert(`File uploaded successfully: ${uploadResult.message}`);

        // Refresh the file lists after upload
        if(uploadResponse.ok) {
            const uploadResponse = await fetch("/upload", {
                method: "GET",
                headers: { 
                    "Authorization": `Bearer ${localStorage.getItem("jwt")}`
                }
            });
            if (uploadResponse.ok) {
                const html = await uploadResponse.text();
                document.getElementById("upload").innerHTML = html;
            } else {
                document.getElementById("upload").innerHTML = "Failed to load files. Please log in again.";
            }
            
            const ownListResponse = await fetch("/ownlist", {
                method: "GET",
                headers: { 
                    "Authorization": `Bearer ${localStorage.getItem("jwt")}`
                }
            });
            if (ownListResponse.ok) {
                const html = await ownListResponse.text();
                document.getElementById("ownlist").innerHTML = html;
            } else {
                document.getElementById("ownlist").innerHTML = "Failed to load files. Please log in again.";
            }

            const sharedListResponse = await fetch("/sharedlist", {
                method: "GET",
                headers: {
                    "Authorization": `Bearer ${localStorage.getItem("jwt")}`
                }
            });
            if (sharedListResponse.ok) {
                const html = await sharedListResponse.text();
                document.getElementById("sharedlist").innerHTML = html;
            } else {
                document.getElementById("sharedlist").innerHTML = "Failed to load shared files. Please log in again.";
            }

        }
    }


    // download files
    window.downloadFile = async function(filename, event) {
        // const jwt = localStorage.getItem("jwt");
        const fileId = event.target.getAttribute('data-field');
        // to-do: use POST request instead
        const response = await fetch(`/download?file_id=${encodeURIComponent(fileId)}`, {
            method: "GET",
            headers: {
                "Authorization": `Bearer ${localStorage.getItem("jwt")}`
            }
        });
        if (response.ok) {
            // Get the response as a Blob and extract each component
            const blob = await response.blob();
            const blobArrayBuffer = await blob.arrayBuffer()
            const blobData = new Uint8Array(blobArrayBuffer);
            const iv = blobData.slice(0, 12);
            const encryptedEDek = blobData.slice(12, 12+256);
            const encryptedFile = blobData.slice(12+256);
            alert(`IV: ${btoa(String.fromCharCode(...iv))}`);
            alert(`Encrypted DEK: ${btoa(String.fromCharCode(...encryptedEDek))}`);
            
            // Send eDek to KMS to unwrap it
            function arrayBufferToBase64(buffer) {
                let binary = '';
                const bytes = buffer
                for (let i = 0; i < bytes.byteLength; i++) {
                    binary += String.fromCharCode(bytes[i]);
                }
                return btoa(binary);
            }
            // alert(`Encrypted DEK length: ${encryptedEDek.byteLength}`);
            const encryptedEDekBase64 = arrayBufferToBase64(encryptedEDek);

            const kmsKEkResponse = await fetch(KMS_ADDRESS + "kms", {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${localStorage.getItem("jwt")}`,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({eDek: (encryptedEDekBase64), file_id: fileId, operation: "download"})
            });
            if (!kmsKEkResponse.ok) {
                alert("Not having permission to access Kek");
                return
            }

            const unwrappedDek = await kmsKEkResponse.json();
            alert(`Unwrapped DEK: ${unwrappedDek.dek}`);

            // Decode and import the DEK
            function base64ToArrayBuffer(base64) {
                const binary = atob(base64);
                const len = binary.length;
                const bytes = new Uint8Array(len);
                for (let i = 0; i < len; i++) {
                    bytes[i] = binary.charCodeAt(i);
                }
                return bytes.buffer;
            }
            dekBuffer = base64ToArrayBuffer(unwrappedDek.dek);
            // alert("successfully get Dek")

            const importedDek = await crypto.subtle.importKey(
                "raw",
                dekBuffer,
                { name: "AES-GCM" },
                false,
                ["decrypt"]
            )
            // alert("successfully import Dek")

            // Decrypt file
            const decryptedFile = await crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: iv,
                },
                importedDek,
                encryptedFile // encryptedFile.buffer.slice(encryptedFile.byteOffset, encryptedFile.byteOffset + encryptedFile.byteLength)
            );
            // alert("decrypt file successfully")

            // wrap the file binary into blob and download the file
            const fileBlob = new Blob([decryptedFile], { type: "application/octet-stream" });

            const url = URL.createObjectURL(fileBlob);
            const a = document.createElement("a");
            a.href = url;
            a.download = filename.replace(/\.enc$/, "");
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
        } else {
            alert("Failed to download file.");
        }
    };


    // share file
    window.shareFile = async function(filename, event) {
        const fileId = event.target.getAttribute("data-field");
        const shareWith = prompt("Enter the username to share this file with:");
        if (!shareWith) {
            alert("No username entered.");
            return;
        }

        const jwt = localStorage.getItem("jwt");
        const response = await fetch("/share", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${localStorage.getItem("jwt")}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({file_id: fileId, share_with: shareWith})
        });

        if(response.ok) {
            const result = await response.json();
            alert(result.message || "Share request sent.");
        } else {
            alert("Failed to share file.")
        }

    }

}


// to-do: erasing key
//        protect jwt from replay
//        use POST if there's arguments to be sent along request