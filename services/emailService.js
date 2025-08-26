

const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'gmail', 
    auth: {
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS  
    }
});


// --- REPLACE YOUR EXISTING FUNCTION WITH THIS ENTIRE BLOCK ---
const sendNewOrderNotification = async (order) => {

    // The entire HTML is built here in one go.
    const htmlBody = `
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f9f6f2;">
            <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="border-collapse: collapse; margin-top: 20px; margin-bottom: 20px; border: 1px solid #e0e0e0; background-color: #ffffff;">
                
                <!-- Main Content -->
                <tr>
                    <td style="padding: 40px 30px;">
                        <h1 style="font-family: 'Times New Roman', Times, serif; color: #333333;">You've Received a New Order!</h1>
                        <p style="color: #555555; font-size: 16px; line-height: 1.5;">
                            A new order has been placed on your website. Please see the details below.
                        </p>
                        
                        <!-- Order Details Table -->
                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-top: 20px; border-top: 1px solid #eeeeee;">
                            <tr>
                                <td style="padding: 10px 0; color: #777777;">Order ID:</td>
                                <td style="padding: 10px 0; color: #333333; font-weight: bold;">${order._id}</td>
                            </tr>
                            <tr>
                                <td style="padding: 10px 0; color: #777777; border-top: 1px solid #eeeeee;">Customer:</td>
                                <td style="padding: 10px 0; color: #333333; font-weight: bold; border-top: 1px solid #eeeeee;">${order.customer.fullName}</td>
                            </tr>
                            <tr>
                                <td style="padding: 10px 0; color: #777777; border-top: 1px solid #eeeeee;">Phone:</td>
                                <td style="padding: 10px 0; color: #333333; font-weight: bold; border-top: 1px solid #eeeeee;">${order.customer.phone}</td>
                            </tr>
                             <tr>
                                <td style="padding: 10px 0; color: #777777; border-top: 1px solid #eeeeee;">Wilaya:</td>
                                <td style="padding: 10px 0; color: #333333; font-weight: bold; border-top: 1px solid #eeeeee;">${order.customer.wilaya}</td>
                            </tr>
                            <tr>
                                <td style="padding: 10px 0; color: #777777; border-top: 1px solid #eeeeee;">Total:</td>
                                <td style="padding: 10px 0; color: #333333; font-weight: bold; font-size: 18px; border-top: 1px solid #eeeeee;">${order.total}</td>
                            </tr>
                        </table>

                        <h3 style="font-family: 'Times New Roman', Times, serif; color: #333333; border-top: 2px solid #eeeeee; padding-top: 20px; margin-top: 30px;">Items Ordered:</h3>
                        <ul style="color: #555555; font-size: 16px; line-height: 1.5; list-style-type: none; padding-left: 0;">
                            ${order.items.map(item => `<li style="padding: 5px 0;">${item.quantity} x ${item.name}</li>`).join('')}
                        </ul>
                    </td>
                </tr>
                <!-- Footer -->
                <tr>
                    <td align="center" style="background-color: #fffaf8; padding: 20px 30px; color: #888888; font-size: 12px;">
                        <p>This is an automated notification. Please log in to the admin dashboard to process this order.</p>
                        <p>© ${new Date().getFullYear()} Bloom. All rights reserved.</p>
                    </td>
                </tr>
            </table>
        </body>
    `;

    // The plain text body is still useful for email clients that don't render HTML
    let textBody = `You have received a new order!\n\nOrder ID: ${order._id}\nCustomer: ${order.customer.fullName}\nTotal: ${order.total}\n\nItems:\n`;
    order.items.forEach(item => {
        textBody += `- ${item.quantity} x ${item.name}\n`;
    });

    try {
        let info = await transporter.sendMail({
            from: `"Bloom Admin" <${process.env.EMAIL_USER}>`,
            to: process.env.EMAIL_USER,
            subject: `New Order Received - #${order._id}`,
            text: textBody,
            html: htmlBody
        });
        console.log('Email notification sent successfully:', info.messageId);
    } catch (error) {
        console.error('Error sending email notification:', error);
    }
};


// --- MODIFICATION START: Add new function for password reset ---
const sendPasswordResetEmail = async (userEmail, token) => {
    const resetUrl = `http://localhost:3000/reset-password/${token}`;

    const htmlBody = `
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f9f6f2;">
            <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="border-collapse: collapse; margin-top: 20px; margin-bottom: 20px; border: 1px solid #e0e0e0; background-color: #ffffff;">
                <tr>
                    <td style="padding: 40px 30px;">
                        <h1 style="font-family: 'Times New Roman', Times, serif; color: #333333;">Réinitialisation de votre mot de passe</h1>
                        <p style="color: #555555; font-size: 16px; line-height: 1.5;">
                            Vous recevez cet email car vous (ou quelqu'un d'autre) avez demandé la réinitialisation du mot de passe de votre compte.
                        </p>
                        <p style="color: #555555; font-size: 16px; line-height: 1.5;">
                            Veuillez cliquer sur le bouton ci-dessous pour choisir un nouveau mot de passe. Ce lien expirera dans une heure.
                        </p>
                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-top: 20px;">
                            <tr>
                                <td align="center">
                                    <a href="${resetUrl}" target="_blank" style="background-color: #D9B8B4; color: #ffffff; padding: 15px 25px; text-decoration: none; border-radius: 8px; font-weight: bold; display: inline-block;">Réinitialiser le mot de passe</a>
                                </td>
                            </tr>
                        </table>
                        <p style="color: #555555; font-size: 16px; line-height: 1.5; margin-top: 30px;">
                            Si vous n'avez pas demandé cette réinitialisation, veuillez ignorer cet email et votre mot de passe restera inchangé.
                        </p>
                    </td>
                </tr>
                <tr>
                    <td align="center" style="background-color: #fffaf8; padding: 20px 30px; color: #888888; font-size: 12px;">
                        <p>© ${new Date().getFullYear()} Bloom. All rights reserved.</p>
                    </td>
                </tr>
            </table>
        </body>
    `;

    const textBody = `Vous recevez cet email car vous (ou quelqu'un d'autre) avez demandé la réinitialisation du mot de passe de votre compte.\n\n` +
                     `Veuillez cliquer sur le lien suivant, ou le copier-coller dans votre navigateur pour compléter le processus :\n\n` +
                     `${resetUrl}\n\n` +
                     `Si vous n'avez pas demandé cette réinitialisation, veuillez ignorer cet email et votre mot de passe restera inchangé.\n`;

    try {
        await transporter.sendMail({
            from: `"Bloom" <${process.env.EMAIL_USER}>`,
            to: userEmail,
            subject: 'Réinitialisation de votre mot de passe Bloom',
            text: textBody,
            html: htmlBody
        });
        console.log(`Password reset email sent successfully to ${userEmail}`);
    } catch (error) {
        console.error('Error sending password reset email:', error);
        throw error; // Re-throw to let the calling route handle the error
    }
};
// --- MODIFICATION END ---



// --- ADD THIS NEW FUNCTION FOR THE CONTACT FORM ---
const sendContactFormEmail = async (fromName, fromEmail, subject, message) => {
    const adminEmail = process.env.EMAIL_USER; // Sending to the primary app email

    const htmlBody = `
        <body style="font-family: Arial, sans-serif; color: #333;">
            <div style="max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
                <h2 style="font-family: 'Times New Roman', Times, serif; color: #4A4A4A;">Nouveau Message via le Formulaire de Contact</h2>
                <p>Vous avez reçu un nouveau message depuis le site Bloom.</p>
                <hr style="border: 0; border-top: 1px solid #eee;">
                <p><strong>De :</strong> ${fromName}</p>
                <p><strong>Email (pour répondre) :</strong> <a href="mailto:${fromEmail}">${fromEmail}</a></p>
                <p><strong>Sujet :</strong> ${subject}</p>
                <h3 style="margin-top: 20px; font-family: 'Times New Roman', Times, serif;">Message :</h3>
                <div style="background-color: #f9f9f9; padding: 15px; border-radius: 4px; white-space: pre-wrap;">${message}</div>
            </div>
        </body>
    `;

    const textBody = `Nouveau message depuis le site Bloom.\n\n` +
                     `De: ${fromName}\n` +
                     `Email (pour répondre): ${fromEmail}\n` +
                     `Sujet: ${subject}\n\n` +
                     `Message:\n${message}`;

    try {
        await transporter.sendMail({
            from: `"Bloom - Contact" <${process.env.EMAIL_USER}>`,
            to: adminEmail,
            replyTo: fromEmail, // CRITICAL: This allows direct replies to the user
            subject: `Nouveau Message de ${fromName} - Sujet: ${subject}`,
            text: textBody,
            html: htmlBody
        });
        console.log(`Contact form email sent successfully from ${fromEmail}`);
    } catch (error) {
        console.error('Error sending contact form email:', error);
        throw error; // Re-throw to be handled by the route
    }
};


// --- MODIFICATION START: Add new function for email verification ---
const sendVerificationEmail = async (userEmail, token) => {
    const verificationUrl = `http://localhost:3000/verify-email/${token}`;

    const htmlBody = `
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f9f6f2;">
            <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="border-collapse: collapse; margin-top: 20px; margin-bottom: 20px; border: 1px solid #e0e0e0; background-color: #ffffff;">
                <tr>
                    <td style="padding: 40px 30px;">
                        <h1 style="font-family: 'Times New Roman', Times, serif; color: #333333;">Bienvenue chez Bloom !</h1>
                        <p style="color: #555555; font-size: 16px; line-height: 1.5;">
                            Merci de vous être inscrit(e). Pour activer votre compte, veuillez cliquer sur le bouton ci-dessous.
                        </p>
                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-top: 20px;">
                            <tr>
                                <td align="center">
                                    <a href="${verificationUrl}" target="_blank" style="background-color: #D9B8B4; color: #ffffff; padding: 15px 25px; text-decoration: none; border-radius: 8px; font-weight: bold; display: inline-block;">Vérifier mon Email</a>
                                </td>
                            </tr>
                        </table>
                        <p style="color: #555555; font-size: 16px; line-height: 1.5; margin-top: 30px;">
                            Si vous n'avez pas créé de compte, veuillez ignorer cet email.
                        </p>
                    </td>
                </tr>
                <tr>
                    <td align="center" style="background-color: #fffaf8; padding: 20px 30px; color: #888888; font-size: 12px;">
                        <p>© ${new Date().getFullYear()} Bloom. All rights reserved.</p>
                    </td>
                </tr>
            </table>
        </body>
    `;

    const textBody = `Bienvenue chez Bloom !\n\n` +
                     `Pour activer votre compte, veuillez cliquer sur le lien suivant, ou le copier-coller dans votre navigateur :\n\n` +
                     `${verificationUrl}\n\n` +
                     `Si vous n'avez pas créé de compte, veuillez ignorer cet email.\n`;

    try {
        await transporter.sendMail({
            from: `"Bloom" <${process.env.EMAIL_USER}>`,
            to: userEmail,
            subject: 'Veuillez vérifier votre adresse email pour Bloom',
            text: textBody,
            html: htmlBody
        });
        console.log(`Verification email sent successfully to ${userEmail}`);
    } catch (error) {
        console.error('Error sending verification email:', error);
        throw error; // Re-throw to be handled by the registration route
    }
};
// --- MODIFICATION END ---


module.exports = {
    sendNewOrderNotification,
    sendPasswordResetEmail,
    sendContactFormEmail,
    sendVerificationEmail // --- MODIFICATION: Export the new function
};

