package com.quorum.tessera.picocli;

import com.quorum.tessera.cli.CliResult;
import com.quorum.tessera.config.*;
import com.quorum.tessera.config.keys.KeyEncryptor;
import com.quorum.tessera.config.keys.KeyEncryptorFactory;
import com.quorum.tessera.config.util.JaxbUtil;
import com.quorum.tessera.encryption.PrivateKey;
import com.quorum.tessera.io.SystemAdapter;
import com.quorum.tessera.passwords.PasswordReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;

@CommandLine.Command(
        name = "keyupdate",
        aliases = {"-updatepassword"},
        headerHeading = "Usage:%n%n",
        synopsisHeading = "%n",
        descriptionHeading = "%nDescription:%n%n",
        parameterListHeading = "%nParameters:%n",
        optionListHeading = "%nOptions:%n",
        header = "Update the password for a key",
        description =
                "Change the password or update the encryption options for an already locked key, or apply a new password to an unlocked key",
        subcommands = {CommandLine.HelpCommand.class},
        abbreviateSynopsis = true)
public class KeyUpdateCommand implements Callable<CliResult> {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyUpdateCommand.class);

    // TODO(cjh) don't hardcode these options (?)

    @CommandLine.Option(names = "--keys.keyData.privateKeyPath", required = true)
    public Path privateKeyPath;

    //    @Pattern(regexp = "^(id|i|d)$")
    //    @XmlAttribute(name = "variant")
    // TODO(cjh) validation on the CLI values - the above is the validation applied to the Config ArgonOptions object
    // fields
    @CommandLine.Option(names = "--keys.keyData.config.data.aopts.algorithm", defaultValue = "i")
    public String algorithm;

    @CommandLine.Option(names = "--keys.keyData.config.data.aopts.iterations", defaultValue = "10")
    public Integer iterations;

    @CommandLine.Option(names = "--keys.keyData.config.data.aopts.memory", defaultValue = "1048576")
    public Integer memory;

    @CommandLine.Option(names = "--keys.keyData.config.data.aopts.parallelism", defaultValue = "4")
    public Integer parallelism;

    @CommandLine.Option(names = {"--keys.passwords"})
    public String password;

    @CommandLine.Option(names = {"--keys.passwordFile"})
    public Path passwordFile;

    @CommandLine.Option(
            names = {"--configfile", "-configfile"},
            description = "Path to node configuration file")
    public Config config;

    @CommandLine.Mixin
    public EncryptorOptions encryptorOptions;

    private KeyEncryptorFactory keyEncryptorFactory;

    private KeyEncryptor keyEncryptor;

    private PasswordReader passwordReader;

    KeyUpdateCommand(KeyEncryptorFactory keyEncryptorFactory, PasswordReader passwordReader) {
        this.keyEncryptorFactory = keyEncryptorFactory;
        this.passwordReader = passwordReader;
    }

    @Override
    public CliResult call() throws Exception {
        final EncryptorConfig encryptorConfig;

        if (Optional.ofNullable(config).map(Config::getEncryptor).isPresent()) {
            encryptorConfig = config.getEncryptor();
        } else {
            encryptorConfig = encryptorOptions.parseEncryptorConfig();
        }

        this.keyEncryptor = keyEncryptorFactory.create(encryptorConfig);

        return execute();
    }

    public CliResult execute() throws IOException {
        final ArgonOptions argonOptions = argonOptions();
        final List<String> passwords = passwords();
        final Path keypath = privateKeyPath();

        final KeyDataConfig keyDataConfig = JaxbUtil.unmarshal(Files.newInputStream(keypath), KeyDataConfig.class);
        final PrivateKey privateKey = this.getExistingKey(keyDataConfig, passwords);

        final String newPassword = passwordReader.requestUserPassword();

        final KeyDataConfig updatedKey;
        if (newPassword.isEmpty()) {
            final PrivateKeyData privateKeyData =
                    new PrivateKeyData(privateKey.encodeToBase64(), null, null, null, null);
            updatedKey = new KeyDataConfig(privateKeyData, PrivateKeyType.UNLOCKED);
        } else {
            final PrivateKeyData privateKeyData = keyEncryptor.encryptPrivateKey(privateKey, newPassword, argonOptions);
            updatedKey = new KeyDataConfig(privateKeyData, PrivateKeyType.LOCKED);
        }

        // write the key to file
        Files.write(keypath, JaxbUtil.marshalToString(updatedKey).getBytes(UTF_8));
        SystemAdapter.INSTANCE.out().println("Private key at " + keypath.toString() + " updated.");

        //        return Optional.empty();
        // TODO(cjh) compare with existing behaviour
        return new CliResult(1, true, null);
    }

    private PrivateKey getExistingKey(final KeyDataConfig kdc, final List<String> passwords) {

        if (kdc.getType() == PrivateKeyType.UNLOCKED) {
            byte[] privateKeyData = Base64.getDecoder().decode(kdc.getValue().getBytes(UTF_8));
            return PrivateKey.from(privateKeyData);
        } else {

            for (final String pass : passwords) {
                try {
                    return PrivateKey.from(keyEncryptor.decryptPrivateKey(kdc.getPrivateKeyData(), pass).getKeyBytes());
                } catch (final Exception e) {
                    LOGGER.debug("Password failed to decrypt. Trying next if available.");
                }
            }

            throw new IllegalArgumentException("Locked key but no valid password given");
        }
    }

    private Path privateKeyPath() {
        ////      TODO(cjh)shouldn't need this as the option should be marked as required - CHECK!
        //        if (privateKeyPath == null) {
        //            throw new IllegalArgumentException("Private key path cannot be null when updating key password");
        //        }

        if (Files.notExists(privateKeyPath)) {
            throw new IllegalArgumentException("Private key path must exist when updating key password");
        }

        return privateKeyPath;
    }

    private List<String> passwords() throws IOException {
        if (password != null) {
            return singletonList(password);
        } else if (passwordFile != null) {
            return Files.readAllLines(passwordFile);
        } else {
            return emptyList();
        }
    }

    private ArgonOptions argonOptions() {
        return new ArgonOptions(
                algorithm, Integer.valueOf(iterations), Integer.valueOf(memory), Integer.valueOf(parallelism));
    }
}