PGDMP         8                |         	   sampledb2    15.5    15.5                0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false                       0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false                       0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false                       1262    24647 	   sampledb2    DATABASE     �   CREATE DATABASE sampledb2 WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'English_Indonesia.1252';
    DROP DATABASE sampledb2;
                postgres    false            �            1259    24656    useraccount    TABLE     �   CREATE TABLE public.useraccount (
    id integer NOT NULL,
    username character varying(100) NOT NULL,
    password character varying(500) NOT NULL
);
    DROP TABLE public.useraccount;
       public         heap    postgres    false            �            1259    24655    useraccount_id_seq    SEQUENCE     �   CREATE SEQUENCE public.useraccount_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 )   DROP SEQUENCE public.useraccount_id_seq;
       public          postgres    false    215                       0    0    useraccount_id_seq    SEQUENCE OWNED BY     I   ALTER SEQUENCE public.useraccount_id_seq OWNED BY public.useraccount.id;
          public          postgres    false    214            �            1259    32830    users    TABLE     F   CREATE TABLE public.users (
    id integer NOT NULL,
    name text
);
    DROP TABLE public.users;
       public         heap    postgres    false            �            1259    32829    users_id_seq    SEQUENCE     �   CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 #   DROP SEQUENCE public.users_id_seq;
       public          postgres    false    217            	           0    0    users_id_seq    SEQUENCE OWNED BY     =   ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;
          public          postgres    false    216            j           2604    24659    useraccount id    DEFAULT     p   ALTER TABLE ONLY public.useraccount ALTER COLUMN id SET DEFAULT nextval('public.useraccount_id_seq'::regclass);
 =   ALTER TABLE public.useraccount ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    214    215    215            k           2604    32833    users id    DEFAULT     d   ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);
 7   ALTER TABLE public.users ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    216    217    217            �          0    24656    useraccount 
   TABLE DATA           =   COPY public.useraccount (id, username, password) FROM stdin;
    public          postgres    false    215   �                 0    32830    users 
   TABLE DATA           )   COPY public.users (id, name) FROM stdin;
    public          postgres    false    217   :       
           0    0    useraccount_id_seq    SEQUENCE SET     A   SELECT pg_catalog.setval('public.useraccount_id_seq', 13, true);
          public          postgres    false    214                       0    0    users_id_seq    SEQUENCE SET     ;   SELECT pg_catalog.setval('public.users_id_seq', 1, false);
          public          postgres    false    216            m           2606    24663    useraccount useraccount_pkey 
   CONSTRAINT     Z   ALTER TABLE ONLY public.useraccount
    ADD CONSTRAINT useraccount_pkey PRIMARY KEY (id);
 F   ALTER TABLE ONLY public.useraccount DROP CONSTRAINT useraccount_pkey;
       public            postgres    false    215            o           2606    32837    users users_pkey 
   CONSTRAINT     N   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);
 :   ALTER TABLE ONLY public.users DROP CONSTRAINT users_pkey;
       public            postgres    false    217            �   �  x�u��n\7E��cօ(��䝛�-�N3�,�n(�JN�4q��4НQ<m�@��^���僞n.��=>�u��*�/���T��^�?���cZ��%,�V8[/�����r�l"&s��ncr)�� +5�Ơ��+�2DR*ڹw�5p蚄��]��˷�;����%�������S�-W7�O��_.m�Y����b+�j��"C��*��/�1��j�_@�*�P&�i�6@��)�4�ɳF�5A��Yh��-����6��r�������7�}w�����$��5pZ��5��b
Y6�T�&LȣS�|Y�(ő�p��+ o�DښQ�S`�6E1�I�`l ;�Ow���K����ͱ��޿>��M�}/>Zʶ*t̹y�4�L��-z��g󬘫.P8����4n��Yk�9I��4�w��`ɲYs�V9�F��G��N?}�{���ݶW��o�o﮾���B]Aɜ�[Ȩ������X�j��K+XFM�6qp�)iJ��P�O��aQ
���t��37&�!�'U-ɬ�����e<���^]����HܴH�3���v{h�P�=�E��l�}��F�ܙ���!ֶ�t�A�o>�ݗ�rR�V&s�-�c�`��k��m���P#�            x������ � �     