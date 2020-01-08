package com.quorum.tessera.config.cli;

import com.quorum.tessera.cli.CliException;
import com.quorum.tessera.cli.CliResult;
import com.quorum.tessera.config.*;
import com.quorum.tessera.key.generation.KeyGenerator;
import com.quorum.tessera.key.generation.KeyGeneratorFactory;
import com.quorum.tessera.key.generation.KeyVaultOptions;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class KeyGenCommandTest {

    private KeyGenCommand command;

    private KeyGeneratorFactory keyGeneratorFactory;

    private final CliResult wantResult = new CliResult(0, true, null);

    @Before
    public void onSetup() {
        keyGeneratorFactory = mock(KeyGeneratorFactory.class);
        command = new KeyGenCommand(keyGeneratorFactory);
    }

    @After
    public void onTearDown() {
        verifyNoMoreInteractions(keyGeneratorFactory);
    }

    @Test
    public void usesDefaultEncryptorConfigIfNoneInConfig() {
        final EncryptorConfig encryptorConfig = new EncryptorConfig();
        final Map<String, String> properties = new HashMap<>();
        encryptorConfig.setType(EncryptorType.NACL);
        encryptorConfig.setProperties(properties);

        final EncryptorOptions encryptorOptions = mock(EncryptorOptions.class);
        when(encryptorOptions.parseEncryptorConfig()).thenReturn(encryptorConfig);

        command.encryptorOptions = encryptorOptions;

        final KeyGenerator keyGenerator = mock(KeyGenerator.class);
        when(keyGeneratorFactory.create(any(), any())).thenReturn(keyGenerator);

        CliResult result = command.call();

        // verify the correct config is used
        verify(keyGeneratorFactory).create(null, encryptorConfig);
        assertThat(result).isEqualToComparingFieldByField(wantResult);

        verify(encryptorOptions).parseEncryptorConfig();
        verify(keyGenerator).generate(anyString(), any(), any());
        verifyNoMoreInteractions(encryptorOptions, keyGenerator);
    }

    @Test
    public void doNotUseEncryptorOptionsIfConfigHasEncryptorConfig() {
        final EncryptorOptions encryptorOptions = mock(EncryptorOptions.class);

        final EncryptorConfig encryptorConfig = new EncryptorConfig();
        final Map<String, String> properties = new HashMap<>();
        encryptorConfig.setType(EncryptorType.NACL);
        encryptorConfig.setProperties(properties);
        final Config config = new Config();
        config.setEncryptor(encryptorConfig);

        command.encryptorOptions = encryptorOptions;
        command.config = config;

        final KeyGenerator keyGenerator = mock(KeyGenerator.class);
        when(keyGeneratorFactory.create(any(), any())).thenReturn(keyGenerator);

        CliResult result = command.call();

        // verify the correct config is used
        verify(keyGeneratorFactory).create(null, encryptorConfig);
        assertThat(result).isEqualToComparingFieldByField(wantResult);

        verify(keyGenerator).generate(anyString(), any(), any());
        verifyNoMoreInteractions(encryptorOptions, keyGenerator);
    }

    @Test
    public void noKeyEncryptionConfigUsesDefault() {
        final ArgonOptions defaultArgonOptions = null;

        final EncryptorConfig encryptorConfig = new EncryptorConfig();
        final Map<String, String> properties = new HashMap<>();
        encryptorConfig.setType(EncryptorType.NACL);
        encryptorConfig.setProperties(properties);

        final EncryptorOptions encryptorOptions = mock(EncryptorOptions.class);
        when(encryptorOptions.parseEncryptorConfig()).thenReturn(encryptorConfig);

        command.encryptorOptions = encryptorOptions;

        final KeyGenerator keyGenerator = mock(KeyGenerator.class);
        when(keyGeneratorFactory.create(any(), any())).thenReturn(keyGenerator);

        CliResult result = command.call();

        // verify the correct config is used
        verify(keyGeneratorFactory).create(null, encryptorConfig);
        assertThat(result).isEqualToComparingFieldByField(wantResult);
        verify(keyGenerator).generate(anyString(), eq(defaultArgonOptions), any());

        verify(encryptorOptions).parseEncryptorConfig();
        verifyNoMoreInteractions(encryptorOptions, keyGenerator);
    }

    @Test
    public void providedKeyEncryptionConfigIsUsed() {
        final ArgonOptions argonOptions = new ArgonOptions();

        final EncryptorConfig encryptorConfig = new EncryptorConfig();
        final Map<String, String> properties = new HashMap<>();
        encryptorConfig.setType(EncryptorType.NACL);
        encryptorConfig.setProperties(properties);

        final EncryptorOptions encryptorOptions = mock(EncryptorOptions.class);
        when(encryptorOptions.parseEncryptorConfig()).thenReturn(encryptorConfig);

        command.encryptorOptions = encryptorOptions;
        command.argonOptions = argonOptions;

        final KeyGenerator keyGenerator = mock(KeyGenerator.class);
        when(keyGeneratorFactory.create(any(), any())).thenReturn(keyGenerator);

        CliResult result = command.call();

        // verify the correct config is used
        verify(keyGeneratorFactory).create(null, encryptorConfig);
        assertThat(result).isEqualToComparingFieldByField(wantResult);
        verify(keyGenerator).generate(anyString(), eq(argonOptions), any());

        verify(encryptorOptions).parseEncryptorConfig();
        verifyNoMoreInteractions(encryptorOptions, keyGenerator);
    }

    @Test
    public void noKeyOutputPathUsesDefault() {
        final String defaultOutputPath = "";

        final EncryptorConfig encryptorConfig = new EncryptorConfig();
        final Map<String, String> properties = new HashMap<>();
        encryptorConfig.setType(EncryptorType.NACL);
        encryptorConfig.setProperties(properties);

        final EncryptorOptions encryptorOptions = mock(EncryptorOptions.class);
        when(encryptorOptions.parseEncryptorConfig()).thenReturn(encryptorConfig);

        command.encryptorOptions = encryptorOptions;

        final KeyGenerator keyGenerator = mock(KeyGenerator.class);
        when(keyGeneratorFactory.create(any(), any())).thenReturn(keyGenerator);

        CliResult result = command.call();

        // verify the correct config is used
        verify(keyGeneratorFactory).create(null, encryptorConfig);
        assertThat(result).isEqualToComparingFieldByField(wantResult);
        verify(keyGenerator).generate(eq(defaultOutputPath), any(), any());

        verify(encryptorOptions).parseEncryptorConfig();
        verifyNoMoreInteractions(encryptorOptions, keyGenerator);
    }

    @Test
    public void providedKeyOutputPathIsUsed() {
        final String outputPath = "mynewkey";

        final EncryptorConfig encryptorConfig = new EncryptorConfig();
        final Map<String, String> properties = new HashMap<>();
        encryptorConfig.setType(EncryptorType.NACL);
        encryptorConfig.setProperties(properties);

        final EncryptorOptions encryptorOptions = mock(EncryptorOptions.class);
        when(encryptorOptions.parseEncryptorConfig()).thenReturn(encryptorConfig);

        command.encryptorOptions = encryptorOptions;
        command.keyOut = Arrays.asList(outputPath);

        final KeyGenerator keyGenerator = mock(KeyGenerator.class);
        when(keyGeneratorFactory.create(any(), any())).thenReturn(keyGenerator);

        CliResult result = command.call();

        // verify the correct config is used
        verify(keyGeneratorFactory).create(null, encryptorConfig);
        assertThat(result).isEqualToComparingFieldByField(wantResult);
        verify(keyGenerator).generate(eq(outputPath), any(), any());

        verify(encryptorOptions).parseEncryptorConfig();
        verifyNoMoreInteractions(encryptorOptions, keyGenerator);
    }

    @Test
    public void multipleKeyOutputPathsGeneratesMultipleKeys() {
        final String outputPath = "mynewkey";
        final String otherOutputPath = "myothernewkey";

        final EncryptorConfig encryptorConfig = new EncryptorConfig();
        final Map<String, String> properties = new HashMap<>();
        encryptorConfig.setType(EncryptorType.NACL);
        encryptorConfig.setProperties(properties);

        final EncryptorOptions encryptorOptions = mock(EncryptorOptions.class);
        when(encryptorOptions.parseEncryptorConfig()).thenReturn(encryptorConfig);

        command.encryptorOptions = encryptorOptions;
        command.keyOut = Arrays.asList(outputPath, otherOutputPath);

        final KeyGenerator keyGenerator = mock(KeyGenerator.class);
        when(keyGeneratorFactory.create(any(), any())).thenReturn(keyGenerator);

        CliResult result = command.call();

        // verify the correct config is used
        verify(keyGeneratorFactory).create(null, encryptorConfig);
        assertThat(result).isEqualToComparingFieldByField(wantResult);
        verify(keyGenerator).generate(eq(outputPath), any(), any());
        verify(keyGenerator).generate(eq(otherOutputPath), any(), any());

        verify(encryptorOptions).parseEncryptorConfig();
        verifyNoMoreInteractions(encryptorOptions, keyGenerator);
    }

    @Test
    public void noKeyVaultOptionsUsesDefault() {
        final KeyVaultOptions defaultKeyVaultOptions = null;

        final EncryptorConfig encryptorConfig = new EncryptorConfig();
        final Map<String, String> properties = new HashMap<>();
        encryptorConfig.setType(EncryptorType.NACL);
        encryptorConfig.setProperties(properties);

        final EncryptorOptions encryptorOptions = mock(EncryptorOptions.class);
        when(encryptorOptions.parseEncryptorConfig()).thenReturn(encryptorConfig);

        command.encryptorOptions = encryptorOptions;

        final KeyGenerator keyGenerator = mock(KeyGenerator.class);
        when(keyGeneratorFactory.create(any(), any())).thenReturn(keyGenerator);

        CliResult result = command.call();

        // verify the correct config is used
        verify(keyGeneratorFactory).create(null, encryptorConfig);
        assertThat(result).isEqualToComparingFieldByField(wantResult);
        verify(keyGenerator).generate(anyString(), any(), eq(defaultKeyVaultOptions));

        verify(encryptorOptions).parseEncryptorConfig();
        verifyNoMoreInteractions(encryptorOptions, keyGenerator);
    }

    @Test
    public void providedKeyVaultOptionsAreUsed() {
        final String keyVaultOptionValue = "somevalue";
        final KeyVaultOptions keyVaultOptions = new KeyVaultOptions(keyVaultOptionValue);

        final EncryptorConfig encryptorConfig = new EncryptorConfig();
        final Map<String, String> properties = new HashMap<>();
        encryptorConfig.setType(EncryptorType.NACL);
        encryptorConfig.setProperties(properties);

        final EncryptorOptions encryptorOptions = mock(EncryptorOptions.class);
        when(encryptorOptions.parseEncryptorConfig()).thenReturn(encryptorConfig);

        command.encryptorOptions = encryptorOptions;
        command.hashicorpSecretEnginePath = keyVaultOptionValue;

        final KeyGenerator keyGenerator = mock(KeyGenerator.class);
        when(keyGeneratorFactory.create(any(), any())).thenReturn(keyGenerator);

        CliResult result = command.call();

        // verify the correct config is used
        verify(keyGeneratorFactory).create(null, encryptorConfig);
        assertThat(result).isEqualToComparingFieldByField(wantResult);
        verify(keyGenerator).generate(anyString(), any(), refEq(keyVaultOptions));

        verify(encryptorOptions).parseEncryptorConfig();
        verifyNoMoreInteractions(encryptorOptions, keyGenerator);
    }

    @Test
    public void validAzureKeyVaultConfig() {
        final KeyVaultConfig keyVaultConfig = new AzureKeyVaultConfig("someurl");

        final EncryptorOptions encryptorOptions = mock(EncryptorOptions.class);
        when(encryptorOptions.parseEncryptorConfig()).thenReturn(null);

        command.encryptorOptions = encryptorOptions;
        command.vaultType = KeyVaultType.AZURE;
        command.vaultUrl = "someurl";

        final KeyGenerator keyGenerator = mock(KeyGenerator.class);
        when(keyGeneratorFactory.create(any(), any())).thenReturn(keyGenerator);

        CliResult result = command.call();

        // verify the correct config is used
        verify(keyGeneratorFactory).create(refEq(keyVaultConfig), isNull());
        assertThat(result).isEqualToComparingFieldByField(wantResult);

        verify(keyGenerator).generate(anyString(), any(), any());
        verify(encryptorOptions).parseEncryptorConfig();
        verifyNoMoreInteractions(encryptorOptions, keyGenerator);
    }

    @Test
    public void invalidAzureKeyVaultConfigThrowsException() {
        final EncryptorOptions encryptorOptions = mock(EncryptorOptions.class);
        when(encryptorOptions.parseEncryptorConfig()).thenReturn(null);

        command.encryptorOptions = encryptorOptions;
        command.vaultType = KeyVaultType.AZURE;

        Throwable ex = catchThrowable(() -> command.call());

        assertThat(ex).isInstanceOf(ConstraintViolationException.class);

        Set<ConstraintViolation<?>> violations = ((ConstraintViolationException) ex).getConstraintViolations();

        assertThat(violations.size()).isEqualTo(1);

        ConstraintViolation violation = violations.iterator().next();

        assertThat(violation.getPropertyPath().toString()).isEqualTo("url");
        assertThat(violation.getMessage()).isEqualTo("may not be null");

        verify(encryptorOptions).parseEncryptorConfig();
        verifyNoMoreInteractions(encryptorOptions);
    }

    @Test
    public void validHashicorpKeyVaultConfig() throws Exception {
        final String vaultUrl = "someurl";
        final String approlePath = "someapprole";
        Path tempPath = Files.createTempFile(UUID.randomUUID().toString(), "");
        tempPath.toFile().deleteOnExit();

        final KeyVaultConfig keyVaultConfig = new HashicorpKeyVaultConfig(vaultUrl, approlePath, tempPath, tempPath);

        final EncryptorOptions encryptorOptions = mock(EncryptorOptions.class);
        when(encryptorOptions.parseEncryptorConfig()).thenReturn(null);

        command.encryptorOptions = encryptorOptions;
        command.vaultType = KeyVaultType.HASHICORP;
        command.vaultUrl = vaultUrl;
        command.hashicorpApprolePath = approlePath;
        command.hashicorpTlsKeystore = tempPath;
        command.hashicorpTlsTruststore = tempPath;
        command.keyOut = Collections.singletonList("out");

        final KeyGenerator keyGenerator = mock(KeyGenerator.class);
        when(keyGeneratorFactory.create(any(), any())).thenReturn(keyGenerator);

        CliResult result = command.call();

        // verify the correct config is used
        verify(keyGeneratorFactory).create(refEq(keyVaultConfig), isNull());
        assertThat(result).isEqualToComparingFieldByField(wantResult);

        verify(keyGenerator).generate(anyString(), any(), any());
        verify(encryptorOptions).parseEncryptorConfig();
        verifyNoMoreInteractions(encryptorOptions, keyGenerator);
    }

    @Test
    public void hashicorpKeyVaultConfigNoOutputPathsThrowsException() throws Exception {
        final String vaultUrl = "someurl";
        final String approlePath = "someapprole";
        Path tempPath = Files.createTempFile(UUID.randomUUID().toString(), "");
        tempPath.toFile().deleteOnExit();

        final EncryptorOptions encryptorOptions = mock(EncryptorOptions.class);
        when(encryptorOptions.parseEncryptorConfig()).thenReturn(null);

        command.encryptorOptions = encryptorOptions;
        command.vaultType = KeyVaultType.HASHICORP;
        command.vaultUrl = vaultUrl;
        command.hashicorpApprolePath = approlePath;
        command.hashicorpTlsKeystore = tempPath;
        command.hashicorpTlsTruststore = tempPath;

        final KeyGenerator keyGenerator = mock(KeyGenerator.class);
        when(keyGeneratorFactory.create(any(), any())).thenReturn(keyGenerator);

        Throwable ex = catchThrowable(() -> command.call());

        assertThat(ex).isInstanceOf(CliException.class);
        assertThat(ex)
                .hasMessage("At least one -filename must be provided when saving generated keys in a Hashicorp Vault");

        verify(encryptorOptions).parseEncryptorConfig();
        verifyNoMoreInteractions(encryptorOptions);
    }

    @Test
    public void invalidHashicorpKeyVaultConfigThrowsException() {
        final EncryptorOptions encryptorOptions = mock(EncryptorOptions.class);
        when(encryptorOptions.parseEncryptorConfig()).thenReturn(null);

        command.encryptorOptions = encryptorOptions;

        command.vaultType = KeyVaultType.HASHICORP;
        command.keyOut = Collections.singletonList("out");

        final KeyGenerator keyGenerator = mock(KeyGenerator.class);
        when(keyGeneratorFactory.create(any(), any())).thenReturn(keyGenerator);

        Throwable ex = catchThrowable(() -> command.call());

        assertThat(ex).isInstanceOf(ConstraintViolationException.class);

        Set<ConstraintViolation<?>> violations = ((ConstraintViolationException) ex).getConstraintViolations();

        assertThat(violations.size()).isEqualTo(1);

        ConstraintViolation violation = violations.iterator().next();

        assertThat(violation.getPropertyPath().toString()).isEqualTo("url");
        assertThat(violation.getMessage()).isEqualTo("may not be null");

        verify(encryptorOptions).parseEncryptorConfig();
        verifyNoMoreInteractions(encryptorOptions);
    }

    @Test
    public void hashicorpTlsPathsDontExistThrowsException() {
        final String vaultUrl = "someurl";
        final String approlePath = "someapprole";
        final Path nonExistentPath = Paths.get(UUID.randomUUID().toString());

        final EncryptorOptions encryptorOptions = mock(EncryptorOptions.class);
        when(encryptorOptions.parseEncryptorConfig()).thenReturn(null);

        command.encryptorOptions = encryptorOptions;
        command.vaultType = KeyVaultType.HASHICORP;
        command.vaultUrl = vaultUrl;
        command.hashicorpApprolePath = approlePath;
        command.hashicorpTlsKeystore = nonExistentPath;
        command.hashicorpTlsTruststore = nonExistentPath;
        command.keyOut = Collections.singletonList("out");

        final KeyGenerator keyGenerator = mock(KeyGenerator.class);
        when(keyGeneratorFactory.create(any(), any())).thenReturn(keyGenerator);

        Throwable ex = catchThrowable(() -> command.call());

        assertThat(ex).isInstanceOf(ConstraintViolationException.class);

        Set<ConstraintViolation<?>> violations = ((ConstraintViolationException) ex).getConstraintViolations();

        assertThat(violations.size()).isEqualTo(2);

        Iterator<ConstraintViolation<?>> iterator = violations.iterator();

        assertThat(iterator.next().getMessage()).isEqualTo("File does not exist");
        assertThat(iterator.next().getMessage()).isEqualTo("File does not exist");

        // verify the correct config is used
        verify(encryptorOptions).parseEncryptorConfig();
        verifyNoMoreInteractions(encryptorOptions, keyGenerator);
    }

    @Test
    public void validAWSKeyVaultConfig() {
        String endpointUrl = "https://someurl.com";

        final DefaultKeyVaultConfig keyVaultConfig = new DefaultKeyVaultConfig();
        keyVaultConfig.setKeyVaultType(KeyVaultType.AWS);
        keyVaultConfig.setProperty("endpoint", endpointUrl);

        final EncryptorOptions encryptorOptions = mock(EncryptorOptions.class);
        when(encryptorOptions.parseEncryptorConfig()).thenReturn(null);

        command.encryptorOptions = encryptorOptions;
        command.vaultType = KeyVaultType.AWS;
        command.vaultUrl = endpointUrl;

        final KeyGenerator keyGenerator = mock(KeyGenerator.class);
        when(keyGeneratorFactory.create(any(), any())).thenReturn(keyGenerator);

        CliResult result = command.call();

        // verify the correct config is used
        verify(keyGeneratorFactory).create(refEq(keyVaultConfig), isNull());
        assertThat(result).isEqualToComparingFieldByField(wantResult);

        verify(keyGenerator).generate(anyString(), any(), any());
        verify(encryptorOptions).parseEncryptorConfig();
        verifyNoMoreInteractions(encryptorOptions, keyGenerator);
    }

    @Test
    public void validAWSKeyVaultConfigNoVaultUrl() {
        final DefaultKeyVaultConfig keyVaultConfig = new DefaultKeyVaultConfig();
        keyVaultConfig.setKeyVaultType(KeyVaultType.AWS);

        final EncryptorOptions encryptorOptions = mock(EncryptorOptions.class);
        when(encryptorOptions.parseEncryptorConfig()).thenReturn(null);

        command.encryptorOptions = encryptorOptions;
        command.vaultType = KeyVaultType.AWS;

        final KeyGenerator keyGenerator = mock(KeyGenerator.class);
        when(keyGeneratorFactory.create(any(), any())).thenReturn(keyGenerator);

        CliResult result = command.call();

        // verify the correct config is used
        verify(keyGeneratorFactory).create(refEq(keyVaultConfig), isNull());
        assertThat(result).isEqualToComparingFieldByField(wantResult);

        verify(keyGenerator).generate(anyString(), any(), any());
        verify(encryptorOptions).parseEncryptorConfig();
        verifyNoMoreInteractions(encryptorOptions, keyGenerator);
    }

    @Test
    public void invalidAWSKeyVaultConfigThrowsException() {
        final EncryptorOptions encryptorOptions = mock(EncryptorOptions.class);
        when(encryptorOptions.parseEncryptorConfig()).thenReturn(null);

        command.encryptorOptions = encryptorOptions;
        command.vaultType = KeyVaultType.AWS;
        command.vaultUrl = "not a valid url";

        final KeyGenerator keyGenerator = mock(KeyGenerator.class);
        when(keyGeneratorFactory.create(any(), any())).thenReturn(keyGenerator);

        Throwable ex = catchThrowable(() -> command.call());

        assertThat(ex).isInstanceOf(ConstraintViolationException.class);

        Set<ConstraintViolation<?>> violations = ((ConstraintViolationException) ex).getConstraintViolations();

        assertThat(violations.size()).isEqualTo(1);

        ConstraintViolation violation = violations.iterator().next();

        assertThat(violation.getMessage()).isEqualTo("must be a valid AWS service endpoint URL with scheme");

        verify(encryptorOptions).parseEncryptorConfig();
        verifyNoMoreInteractions(encryptorOptions);
    }

    @Test
    public void vaultUrlButNoVaultTypeThrowsException() {
        final EncryptorOptions encryptorOptions = mock(EncryptorOptions.class);
        when(encryptorOptions.parseEncryptorConfig()).thenReturn(null);

        command.encryptorOptions = encryptorOptions;
        command.vaultUrl = "someurl";

        final KeyGenerator keyGenerator = mock(KeyGenerator.class);
        when(keyGeneratorFactory.create(any(), any())).thenReturn(keyGenerator);

        Throwable ex = catchThrowable(() -> command.call());

        assertThat(ex).isInstanceOf(CliException.class);
        assertThat(ex.getMessage()).isEqualTo("Key vault type either not provided or not recognised");

        verify(encryptorOptions).parseEncryptorConfig();
        verifyNoMoreInteractions(encryptorOptions);
    }
}
