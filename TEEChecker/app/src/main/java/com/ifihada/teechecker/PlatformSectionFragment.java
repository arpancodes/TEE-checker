package com.ifihada.teechecker;

import android.annotation.TargetApi;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.security.IKeystoreService;
import android.security.KeyChain;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.lang.reflect.Method;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

public class PlatformSectionFragment extends CheckerFragment
{
  private static final String TAG = "PlatformSectionFragment";
  private static final int NO_ERROR = 1;

  @Override
  public void onCreate(Bundle saved)
  {
    super.onCreate(saved);
    addPreferencesFromResource(R.xml.platform_prefs);
    fill();
  }

  public void fill()
  {
    result("device", String.format("%s %s (%s branded)", Build.MANUFACTURER, Build.MODEL, Build.BRAND));
    result("version", String.format("%s (%s)", Build.VERSION.RELEASE, Build.DISPLAY));

    result("keystore-supported", hasKeystoreApi(), "");
    result("keystore-keytypes", getUsableTypes());
//    result("keystore-hw", hasKeystoreHardware(), "");
    result("keystore-hw-keytypes", getHardwareTypes());
  }

  private IKeystoreService getKeystore()
  {
    try
    {
      Class serviceMgrClass = Class.forName("android.os.ServiceManager");
      Method getService = serviceMgrClass.getMethod("getService", String.class);
      IBinder binder = (IBinder) getService.invoke(null, "android.security.keystore");
      IKeystoreService ks = IKeystoreService.Stub.asInterface(binder);
      return ks;
    } catch (Exception e)
    {
      Log.wtf(TAG, "hasKeystore reflection failed", e);
      return null;
    }
  }

  private static final String[] knownKeyTypes = new String[] { "RSA", "DSA", "EC", "ECDSA", "ECDH", "AES", "DES", "DES3" };
  private static final String KEY_ALIAS = "myKeyAlias";


  private String join(List<String> strs)
  {
    StringBuffer sb = new StringBuffer();
    for (int i = 0; i < strs.size(); i++)
    {
      sb.append(strs.get(i));
      if (i != strs.size() - 1)
        sb.append(", ");
    }
    return sb.toString();
  }

  private String getHardwareTypes()
  {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR2)
      return "(unavailable)";

    ArrayList<String> usable = new ArrayList<String>();
    for (String kt : knownKeyTypes)
    {
      if (isKeyTypeHardwareBacked(kt))
        usable.add(kt);
    }

    if (usable.size() == 0)
      return "(none)";

    return join(usable);
  }

  @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
  private String getUsableTypes()
  {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR2)
      return "(unavailable)";

    ArrayList<String> usable = new ArrayList<String>();
    for (String kt : knownKeyTypes)
    {
      if (KeyChain.isKeyAlgorithmSupported(kt))
        usable.add(kt);
    }

    if (usable.size() == 0)
      return "(none)";

    return join(usable);
  }

  private boolean hasKeystoreApi()
  {
    try {
      boolean hasKeyStore = generateKeyAndCheckSecurityLevel();
      removeKeyFromKeystore();
      return hasKeyStore;
    } catch (Exception e) {
      e.printStackTrace();
    }
    return false;
  }

  private boolean isKeyTypeHardwareBacked(String kt)
  {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
      return KeyChain.isBoundKeyAlgorithm(kt);
    }
    return false;
  }

  private boolean hasKeystoreHardware()
  {
    for (String kt : knownKeyTypes)
      if (isKeyTypeHardwareBacked(kt))
        return true;

    return false;
  }

  private static boolean generateKeyAndCheckSecurityLevel() throws Exception {
    KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
    keyStore.load(null);

    if (!keyStore.containsAlias(KEY_ALIAS)) {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
              KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        keyPairGenerator.initialize(new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .build());
      }

      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      PrivateKey key = keyPair.getPrivate();
      KeyFactory factory = KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
      KeyInfo keyInfo;
      try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
          keyInfo = factory.getKeySpec(key, KeyInfo.class);
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            System.out.println("SECURITY LEVEL: " + keyInfo.getSecurityLevel());
            switch(keyInfo.getSecurityLevel()) {
              case KeyProperties.SECURITY_LEVEL_STRONGBOX:
              case KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT: return true;
              default: return false;
            }
          } else {
            return keyInfo.isInsideSecureHardware();
          }
        }
      } catch (InvalidKeySpecException e) {
        // Not an Android KeyStore key.
      }
      System.out.println("Key generated successfully with alias: " + KEY_ALIAS);
    } else {
      System.out.println("Key with alias " + KEY_ALIAS + " already exists.");
    }
    return false;
  }

  private static void removeKeyFromKeystore() throws Exception {
    KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
    keyStore.load(null);

    // Remove the key entry using the alias
    keyStore.deleteEntry(KEY_ALIAS);

    System.out.println("Key with alias " + KEY_ALIAS + " deleted from keystore.");
  }
}

